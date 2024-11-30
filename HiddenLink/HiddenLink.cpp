#include <fltKernel.h>
#include "file.h"

template<size_t size>
constexpr size_t constexpr_wcslen(const wchar_t (&)[size])
{
    return size - 1;
}

constexpr ULONG HL_TAG = 'HLTG';

PFLT_FILTER gFilterHandle = nullptr;

NTSTATUS
DelProtectUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS CheckPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    auto status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED, &name_info);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    bool call_post_cb = false;

    if (name_info)
    {
        FltParseFileNameInformation(name_info);

        auto context = static_cast<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING), HL_TAG));
        if (context)
        {
            context->MaximumLength = name_info->Name.Length;
            context->Buffer = static_cast<WCHAR*>(ExAllocatePool2(POOL_FLAG_PAGED, name_info->Name.Length, HL_TAG));
            if (context->Buffer) {
                RtlCopyUnicodeString(context, &name_info->Name);
            }
            *CompletionContext = context;
            call_post_cb = true;
        }

        FltReleaseFileNameInformation(name_info);
    }

    if (call_post_cb)
    {
        return FLT_PREOP_SYNCHRONIZE;
    }
    else
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

FLT_POSTOP_CALLBACK_STATUS CheckPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (!CompletionContext)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!(static_cast<PUNICODE_STRING>(CompletionContext)->Buffer))
    {
        ExFreePool(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!Data || !Data->TagData)
    {
        ExFreePool(static_cast<PUNICODE_STRING>(CompletionContext)->Buffer);
        ExFreePool(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Open SYMLINK?
    if (Data->TagData->FileTag != IO_REPARSE_TAG_SYMLINK ||
        Data->IoStatus.Status != STATUS_REPARSE)
    {
        ExFreePool(static_cast<PUNICODE_STRING>(CompletionContext)->Buffer);
        ExFreePool(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Query HiddenLink From EA
    UCHAR raw_eadata[sizeof(FILE_FULL_EA_INFORMATION) + 300*sizeof(wchar_t)] = {};
    auto ret = QueryEaData(FltObjects, static_cast<PUNICODE_STRING>(CompletionContext), raw_eadata, sizeof(raw_eadata));
    if (!ret)
    {
        ExFreePool(static_cast<PUNICODE_STRING>(CompletionContext)->Buffer);
        ExFreePool(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    auto eadata = reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eadata);
    auto valptr = reinterpret_cast<wchar_t*>(eadata->EaName + eadata->EaNameLength + 1);

    auto sym_buffer = &Data->TagData->SymbolicLinkReparseBuffer.PathBuffer[Data->TagData->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(wchar_t)];
    auto sym_buffer_length = Data->TagData->SymbolicLinkReparseBuffer.SubstituteNameLength;
    USHORT hlink_length = eadata->EaValueLength;
    if (!strcmp(eadata->EaName, "$HLINK"))
    {
        // Currently networkpath, unc are not supported

        // only simple check
        bool is_relative_hlink = false;
        if (hlink_length <= 1 || valptr[0] == L'.' ||
            (valptr[0] != L'\\' && valptr[1] != L':'))
        {
            is_relative_hlink = true;
        }

        constexpr wchar_t od_prefix[] = L"\\??\\";
        bool insert_prefix = false;
        if (!is_relative_hlink)
        {
            hlink_length += static_cast<USHORT>(constexpr_wcslen(od_prefix)*sizeof(wchar_t));
            if (!(Data->TagData->SymbolicLinkReparseBuffer.Flags & SYMLINK_FLAG_RELATIVE))
            {
                sym_buffer          += constexpr_wcslen(od_prefix);
                sym_buffer_length   -= static_cast<USHORT>(constexpr_wcslen(od_prefix));
            }
            else
            {
                insert_prefix  = true;
            }
        }

        // To simplify, overwrite if buffer is sufficient
        if (hlink_length <= sym_buffer_length)
        {
            if (is_relative_hlink)
            {
                Data->TagData->SymbolicLinkReparseBuffer.Flags |= SYMLINK_FLAG_RELATIVE;
            }
            else
            {
                Data->TagData->SymbolicLinkReparseBuffer.Flags &= ~SYMLINK_FLAG_RELATIVE;
            }

            Data->TagData->SymbolicLinkReparseBuffer.SubstituteNameLength = hlink_length;
            if (insert_prefix)
            {
                memcpy_s(sym_buffer, sym_buffer_length, od_prefix, constexpr_wcslen(od_prefix)*sizeof(wchar_t));
                sym_buffer          += constexpr_wcslen(od_prefix);
                sym_buffer_length   -= static_cast<USHORT>(constexpr_wcslen(od_prefix)*sizeof(wchar_t));
                hlink_length        -= static_cast<USHORT>(constexpr_wcslen(od_prefix)*sizeof(wchar_t));
            }
            memcpy_s(sym_buffer, sym_buffer_length, valptr, hlink_length);

            FltSetCallbackDataDirty(Data);
            wchar_t tmp[300] = {};
            memcpy_s(tmp, sizeof(tmp), 
                &Data->TagData->SymbolicLinkReparseBuffer.PathBuffer[Data->TagData->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(wchar_t)], 
                Data->TagData->SymbolicLinkReparseBuffer.SubstituteNameLength);
        }
    }

    ExFreePool(static_cast<PUNICODE_STRING>(CompletionContext)->Buffer);
    ExFreePool(CompletionContext);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, CheckPreCreate, CheckPostCreate },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS
DelProtectInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    return STATUS_SUCCESS;
}

NTSTATUS
DelProtectInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    return STATUS_SUCCESS;
}

VOID
DelProtectInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();
}


VOID
DelProtectInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();
}

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                       //  Flags

    nullptr,                 //  Context
    Callbacks,               //  Operation callbacks

    DelProtectUnload,                   //  MiniFilterUnload

    DelProtectInstanceSetup,            //  InstanceSetup
    DelProtectInstanceQueryTeardown,    //  InstanceQueryTeardown
    DelProtectInstanceTeardownStart,    //  InstanceTeardownStart
    DelProtectInstanceTeardownComplete, //  InstanceTeardownComplete
};

NTSTATUS DefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = DefaultDispatcher;
    }

    auto status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = FltStartFiltering(gFilterHandle);

    return status;
}
