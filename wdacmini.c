#include <ntifs.h>
#include <bcrypt.h>
#include "blocked_images.h"

#define WDACMINI_READ_SIZE (64 * 1024)
#define WDACMINI_POOL_TAG 'mcdw'

DRIVER_INITIALIZE DriverEntry;

typedef struct _WDACMINI_FILE_INFO {
    FILE_STANDARD_INFORMATION Standard;
    FILE_BASIC_INFORMATION Basic;
} WDACMINI_FILE_INFO, *PWDACMINI_FILE_INFO;

static NTSTATUS WdacMiniQueryFileInfo(
    _In_ HANDLE FileHandle,
    _Out_ PWDACMINI_FILE_INFO FileInfo)
{
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    RtlZeroMemory(FileInfo, sizeof(*FileInfo));
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwQueryInformationFile(
        FileHandle,
        &ioStatus,
        &FileInfo->Standard,
        sizeof(FileInfo->Standard),
        FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwQueryInformationFile(
        FileHandle,
        &ioStatus,
        &FileInfo->Basic,
        sizeof(FileInfo->Basic),
        FileBasicInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (FileInfo->Standard.Directory ||
        FileInfo->Standard.DeletePending ||
        FileInfo->Standard.EndOfFile.QuadPart < 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static BOOLEAN WdacMiniSameFileInfo(
    _In_ const WDACMINI_FILE_INFO *Left,
    _In_ const WDACMINI_FILE_INFO *Right)
{
    return Left->Standard.EndOfFile.QuadPart == Right->Standard.EndOfFile.QuadPart &&
        Left->Basic.LastWriteTime.QuadPart == Right->Basic.LastWriteTime.QuadPart &&
        Left->Basic.ChangeTime.QuadPart == Right->Basic.ChangeTime.QuadPart;
}

static BOOLEAN WdacMiniHasSize(_In_ ULONGLONG Size)
{
    ULONG index;

    for (index = 0; index < ARRAYSIZE(g_blockedImages); ++index)
    {
        if (g_blockedImages[index].Size == Size)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN WdacMiniMatchesHash(
    _In_ ULONGLONG Size,
    _In_reads_bytes_(WDACMINI_SHA256_SIZE) const UCHAR *Digest)
{
    ULONG index;

    for (index = 0; index < ARRAYSIZE(g_blockedImages); ++index)
    {
        if (g_blockedImages[index].Size == Size &&
            RtlCompareMemory(Digest, g_blockedImages[index].Hash, WDACMINI_SHA256_SIZE) ==
                WDACMINI_SHA256_SIZE)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS WdacMiniHashFile(
    _In_ HANDLE FileHandle,
    _In_ ULONGLONG FileSize,
    _Out_writes_bytes_(WDACMINI_SHA256_SIZE) UCHAR *Digest)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE eventHandle = NULL;
    PKEVENT event = NULL;
    PUCHAR buffer = NULL;
    PUCHAR hashObject = NULL;
    ULONG objectLength = 0;
    ULONG resultLength = 0;
    ULONGLONG offset = 0;
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateEvent(
        &eventHandle,
        EVENT_ALL_ACCESS,
        &attributes,
        NotificationEvent,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(
        eventHandle,
        SYNCHRONIZE | EVENT_MODIFY_STATE,
        *ExEventObjectType,
        KernelMode,
        (PVOID *)&event,
        NULL);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, WDACMINI_READ_SIZE, WDACMINI_POOL_TAG);
    if (buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&objectLength,
        sizeof(objectLength),
        &resultLength,
        0);
    if (!NT_SUCCESS(status) || objectLength == 0)
    {
        if (NT_SUCCESS(status))
        {
            status = STATUS_INVALID_PARAMETER;
        }
        goto Cleanup;
    }

    hashObject = ExAllocatePool2(POOL_FLAG_NON_PAGED, objectLength, WDACMINI_POOL_TAG);
    if (hashObject == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = BCryptCreateHash(
        algorithm,
        &hash,
        hashObject,
        objectLength,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    while (offset < FileSize)
    {
        IO_STATUS_BLOCK ioStatus;
        LARGE_INTEGER byteOffset;
        ULONG chunk;
        ULONG bytesRead;

        chunk = (FileSize - offset > WDACMINI_READ_SIZE)
            ? WDACMINI_READ_SIZE
            : (ULONG)(FileSize - offset);
        byteOffset.QuadPart = (LONGLONG)offset;
        RtlZeroMemory(&ioStatus, sizeof(ioStatus));
        KeClearEvent(event);

        status = ZwReadFile(
            FileHandle,
            eventHandle,
            NULL,
            NULL,
            &ioStatus,
            buffer,
            chunk,
            &byteOffset,
            NULL);
        if (status == STATUS_PENDING)
        {
            (VOID)KeWaitForSingleObject(event, Executive, KernelMode, FALSE, NULL);
            status = ioStatus.Status;
        }
        if (!NT_SUCCESS(status))
        {
            goto Cleanup;
        }

        bytesRead = (ULONG)ioStatus.Information;
        if (bytesRead == 0)
        {
            status = STATUS_END_OF_FILE;
            goto Cleanup;
        }
        if (bytesRead > chunk)
        {
            status = STATUS_DATA_ERROR;
            goto Cleanup;
        }

        status = BCryptHashData(hash, buffer, bytesRead, 0);
        if (!NT_SUCCESS(status))
        {
            goto Cleanup;
        }

        offset += bytesRead;
    }

    status = BCryptFinishHash(hash, Digest, WDACMINI_SHA256_SIZE, 0);

Cleanup:
    if (hash != NULL)
    {
        (VOID)BCryptDestroyHash(hash);
    }
    if (algorithm != NULL)
    {
        (VOID)BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (hashObject != NULL)
    {
        ExFreePoolWithTag(hashObject, WDACMINI_POOL_TAG);
    }
    if (buffer != NULL)
    {
        ExFreePoolWithTag(buffer, WDACMINI_POOL_TAG);
    }
    if (event != NULL)
    {
        ObDereferenceObject(event);
    }
    if (eventHandle != NULL)
    {
        (VOID)ZwClose(eventHandle);
    }
    return status;
}

static BOOLEAN WdacMiniShouldBlock(_In_ HANDLE FileHandle)
{
    UCHAR digest[WDACMINI_SHA256_SIZE];
    ULONG attempt;

    for (attempt = 0; attempt < 2; ++attempt)
    {
        WDACMINI_FILE_INFO before;
        WDACMINI_FILE_INFO after;
        NTSTATUS status;

        status = WdacMiniQueryFileInfo(FileHandle, &before);
        if (!NT_SUCCESS(status) ||
            !WdacMiniHasSize((ULONGLONG)before.Standard.EndOfFile.QuadPart))
        {
            return FALSE;
        }

        status = WdacMiniHashFile(
            FileHandle,
            (ULONGLONG)before.Standard.EndOfFile.QuadPart,
            digest);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        status = WdacMiniQueryFileInfo(FileHandle, &after);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        if (WdacMiniSameFileInfo(&before, &after))
        {
            return WdacMiniMatchesHash(
                (ULONGLONG)before.Standard.EndOfFile.QuadPart,
                digest);
        }
    }

    return FALSE;
}

static VOID NTAPI WdacMiniProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    HANDLE fileHandle;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == NULL || CreateInfo->FileObject == NULL)
    {
        return;
    }

    status = ObOpenObjectByPointer(
        CreateInfo->FileObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        *IoFileObjectType,
        KernelMode,
        &fileHandle);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    if (WdacMiniShouldBlock(fileHandle))
    {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }

    (VOID)ZwClose(fileHandle);
}

static VOID NTAPI WdacMiniUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    (VOID)PsSetCreateProcessNotifyRoutineEx(WdacMiniProcessNotify, TRUE);
}

NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = PsSetCreateProcessNotifyRoutineEx(WdacMiniProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    DriverObject->DriverUnload = WdacMiniUnload;
    return STATUS_SUCCESS;
}
