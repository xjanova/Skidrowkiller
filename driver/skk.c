/*++

    Skidrow Killer — Kernel Filesystem Minifilter (PHASE 1: MONITOR-ONLY)

    ⚠️  SCAFFOLD / STARTING POINT — UNVERIFIED.
        This file is NOT compiled by the .NET solution or its CI. It requires the Windows Driver Kit
        (WDK) + Visual Studio, must be EV/WHQL-signed for production (test-signing for dev), and must be
        reviewed/tested with Driver Verifier in a VM before loading on a real machine. A buggy kernel
        callback can BSOD — Phase 1 is deliberately PASSIVE (it observes file creates and returns
        immediately; it does NOT pend or block I/O). See docs/KERNEL_DRIVER_ARCHITECTURE.md.

    Phase 2 (later) will: open a FltMgr communication port, send each create's path to the user-mode
    engine (ThreatAnalyzer + ReputationService), pend the IRP, and ALLOW/BLOCK on the verdict.

--*/

#include <fltKernel.h>

PFLT_FILTER gFilterHandle = NULL;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS SkkUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
SkkInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
SkkInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
SkkPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

//
//  Operation callbacks — Phase 1 only watches creates.
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SkkPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       //  Size
    FLT_REGISTRATION_VERSION,       //  Version
    0,                              //  Flags
    NULL,                           //  Context registration
    Callbacks,                      //  Operation callbacks
    SkkUnload,                      //  FilterUnload
    SkkInstanceSetup,               //  InstanceSetup
    SkkInstanceQueryTeardown,       //  InstanceQueryTeardown
    NULL,                           //  InstanceTeardownStart
    NULL,                           //  InstanceTeardownComplete
    NULL, NULL, NULL, NULL          //  (name provider / transaction / section callbacks)
};

NTSTATUS
SkkInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    //  Attach to all volumes for now (Phase 2 can filter by filesystem type).
    return STATUS_SUCCESS;
}

NTSTATUS
SkkInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;   //  Always allow detach.
}

FLT_PREOP_CALLBACK_STATUS
SkkPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //  PHASE 1: observe only. Do NOT pend/block — fail-open by design.
    //  Phase 2 will resolve the name (FltGetFileNameInformation), send it to the user-mode
    //  engine over the communication port, and return FLT_PREOP_PENDING until a verdict arrives.
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[skk] IRP_MJ_CREATE observed\n");

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
SkkUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return status;
}
