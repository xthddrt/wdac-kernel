#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;

static const UNICODE_STRING g_blockedNames[] = {
    RTL_CONSTANT_STRING(L"notepad.exe")
};

static VOID NTAPI WdacMiniProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PCUNICODE_STRING imageName;
    UNICODE_STRING fileName;
    USHORT characterCount;
    USHORT start = 0;
    USHORT i;
    ULONG rule;

    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == NULL ||
        !CreateInfo->FileOpenNameAvailable ||
        CreateInfo->ImageFileName == NULL ||
        CreateInfo->ImageFileName->Buffer == NULL)
    {
        return;
    }

    imageName = CreateInfo->ImageFileName;
    characterCount = imageName->Length / sizeof(WCHAR);

    for (i = 0; i < characterCount; ++i)
    {
        if (imageName->Buffer[i] == L'\\')
        {
            start = i + 1;
        }
    }

    fileName.Buffer = &imageName->Buffer[start];
    fileName.Length = (USHORT)((characterCount - start) * sizeof(WCHAR));
    fileName.MaximumLength = fileName.Length;

    for (rule = 0; rule < ARRAYSIZE(g_blockedNames); ++rule)
    {
        if (RtlEqualUnicodeString(&fileName, &g_blockedNames[rule], TRUE))
        {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
    }
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
