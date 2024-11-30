#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG  NextEntryOffset;
    UCHAR  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

// MakeHidden <linkfile> <hiddenlink>
int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        printf("invalid arguments\n");
    }

    constexpr char ea_name[] = "$HLINK";

    // name : "$HLINK"
    // val  : key
    // EaName = <val>\0<key>

    const auto seclink_size = static_cast<USHORT>(wcslen(argv[2])) * sizeof(wchar_t);
    const auto eainfo_size = static_cast<ULONG>(sizeof(FILE_FULL_EA_INFORMATION) + _countof(ea_name) + seclink_size);

    auto raw_eainfo = std::make_unique<BYTE[]>(eainfo_size);
    reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->NextEntryOffset  = 0;
    reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->Flags            = 0;
    reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->EaNameLength     = _countof(ea_name) - 1;
    reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->EaValueLength    = static_cast<USHORT>(seclink_size);

    const auto remain = reinterpret_cast<CHAR*>(raw_eainfo.get()) + eainfo_size - reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->EaName;
    memcpy_s(reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->EaName, remain, ea_name, _countof(ea_name));
    memcpy_s(reinterpret_cast<PFILE_FULL_EA_INFORMATION>(raw_eainfo.get())->EaName + _countof(ea_name),
        remain - _countof(ea_name), argv[2], seclink_size);

    auto linkfile = CreateFileW(argv[1], GENERIC_ALL, 0, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_REPARSE_POINT | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (linkfile == INVALID_HANDLE_VALUE)
    {
        printf("NG %d\n", GetLastError());
    }
    using _ZwSetEaFile = NTSTATUS(NTAPI*)(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length);
    auto ZwSetEaFile = reinterpret_cast<_ZwSetEaFile>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetEaFile"));

    IO_STATUS_BLOCK io = {};
    auto stat = ZwSetEaFile(linkfile, &io, raw_eainfo.get(), eainfo_size);
    if (!NT_SUCCESS(stat))
    {
        printf("NG %x\n", stat);
    }

    CloseHandle(linkfile);

    printf("AllEND\n");
}
