#include "file.h"

bool QueryEaData(PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING filepath, UCHAR *buff, size_t buff_size)
{
    if (!FltObjects || !filepath || !buff || !buff_size)
    {
        return false;
    }

    // open file
    OBJECT_ATTRIBUTES oa = {};
    IO_STATUS_BLOCK io = {};
    HANDLE handle = nullptr;
    PFILE_OBJECT fo = nullptr;
    InitializeObjectAttributes(&oa, filepath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    auto status = FltCreateFileEx(FltObjects->Filter, FltObjects->Instance,
            &handle, &fo,
            FILE_READ_DATA | SYNCHRONIZE,
            &oa, &io, NULL,
            FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            nullptr, 0, IO_IGNORE_SHARE_ACCESS_CHECK );
    if (!NT_SUCCESS(status))
    {
        return false;
    }

    // get ea
    status = FltQueryEaFile(FltObjects->Instance, fo, buff, static_cast<ULONG>(buff_size), FALSE, nullptr, 0, nullptr, TRUE, nullptr);
    FltClose(handle);
    ObDereferenceObject(fo);
    if (!NT_SUCCESS(status))
    {
        return false;
    }
    else
    {
        return true;
    }
}

