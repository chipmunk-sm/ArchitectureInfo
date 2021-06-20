/**************************************************************************************
* https://github.com/chipmunk-sm
* (C) 2021 chipmunk-sm
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
****************************************************************************************/

#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>

enum class ComponentInfo {
    UNKNOWN,
    ANYCPU,
    X86,
    x64,
    rom
};

int64_t GetFileSize(std::wstring path){
    struct __stat64 flstat;
    auto retcode = _wstat64( path.c_str(), &flstat);
    if (retcode == 0)
        return static_cast<int64_t>(flstat.st_size);
    return 0;
}

int64_t rva_to_offset(const IMAGE_SECTION_HEADER *sections, int num_sections, DWORD rva)
{
    for (int i = 0; i < num_sections; i++) {
        if (sections[i].VirtualAddress <= rva && sections[i].VirtualAddress + sections[i].SizeOfRawData > rva) {
            return sections[i].PointerToRawData + rva - sections[i].VirtualAddress;
        }
    }
    return 0;
}

ComponentInfo GetArchitectureInfo(const std::wstring &path) {

    std::ifstream input(path, std::ios::binary );
    if (!input)
        return ComponentInfo::UNKNOWN;

    IMAGE_DOS_HEADER image_dos_header = {};

    input.seekg(0, std::ios_base::beg);
    if (!input)
        return ComponentInfo::UNKNOWN;

    input.read(reinterpret_cast<char*>(&image_dos_header), sizeof (IMAGE_DOS_HEADER));
    if (!input)
        return ComponentInfo::UNKNOWN;

    if (image_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return ComponentInfo::UNKNOWN;

    IMAGE_NT_HEADERS32 image_nt_headers32;
    input.seekg(image_dos_header.e_lfanew, std::ios_base::beg);
    if (!input)
        return ComponentInfo::UNKNOWN;

    input.read(reinterpret_cast<char*>(&image_nt_headers32), sizeof (image_nt_headers32));
    if (!input)
        return ComponentInfo::UNKNOWN;
    if (image_nt_headers32.Signature != IMAGE_NT_SIGNATURE)
        return ComponentInfo::UNKNOWN;

    auto isRom = image_nt_headers32.OptionalHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC;
    if(isRom)
        return ComponentInfo::rom;

    auto isX64 = image_nt_headers32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (isX64)
        return ComponentInfo::x64;

    auto isX86 = image_nt_headers32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    if(!isX86)
        return ComponentInfo::UNKNOWN;

    if (image_nt_headers32.FileHeader.NumberOfSections && image_nt_headers32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size) {

        std::vector<IMAGE_SECTION_HEADER> hdr(image_nt_headers32.FileHeader.NumberOfSections);

        input.seekg(static_cast<int64_t>(image_dos_header.e_lfanew + sizeof(image_nt_headers32)), std::ios_base::beg);
        if (!input)
            return ComponentInfo::UNKNOWN;

        input.read(reinterpret_cast<char*>(hdr.data()), static_cast<int64_t>(sizeof (IMAGE_SECTION_HEADER) * hdr.size()));
        if (!input)
            return ComponentInfo::UNKNOWN;

        auto numberOfSections = image_nt_headers32.FileHeader.NumberOfSections;
        auto virtualAddress = image_nt_headers32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        auto offset = rva_to_offset(hdr.data(), numberOfSections, virtualAddress);

        input.seekg(offset, std::ios_base::beg);
        if (!input)
            return ComponentInfo::UNKNOWN;

        IMAGE_COR20_HEADER image_cor20_header = {};

        input.read(reinterpret_cast<char*>(&image_cor20_header), sizeof (image_cor20_header));
        if (!input)
            return ComponentInfo::UNKNOWN;

        if ((image_cor20_header.Flags & COMIMAGE_FLAGS_32BITREQUIRED) == 0)
            return ComponentInfo::ANYCPU;
    }

    return ComponentInfo::X86;
}

int wmain(int argc, wchar_t *argv[])
{

    HANDLE hStdConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    std::wstring path;

    if (argc > 2) {
        std::wcerr << "Usage: " << argv[0] << " \"path to folder\"" << std::endl;
        return 1;
    } else if(argc == 2) {
        path = argv[1];
    } else{
        wchar_t currentPath[MAX_PATH + 2] = {};
        GetCurrentDirectoryW(MAX_PATH, currentPath);
        path = currentPath;
    }

    //for(int ind = 1; ind < 255; ind++) {
    //    SetConsoleTextAttribute(hConsole, ind);
    //    std::wcout << ind << " test console color  " << std::endl;
    //}
    try {

        if (std::filesystem::exists(path)) {
            for (const auto & fd : std::filesystem::directory_iterator(path)) {

                std::wstring itemExtension = fd.path().extension();
                std::transform(itemExtension.begin(), itemExtension.end(), itemExtension.begin(), ::tolower);
                if(!(itemExtension == L".dll" || itemExtension == L".exe"))
                    continue;

                std::wstring itemPath = fd.path();
                //auto size = GetFileSize(itemPath);

                std::wstring sResult;
                auto result = GetArchitectureInfo(itemPath);
                switch (result) {
                case ComponentInfo::ANYCPU: sResult = L"AnyCpu"; SetConsoleTextAttribute(hStdConsole, 31); break;
                case ComponentInfo::X86: sResult = L"x86"; SetConsoleTextAttribute(hStdConsole, 30); break;
                case ComponentInfo::x64: sResult = L"x64"; SetConsoleTextAttribute(hStdConsole, 26); break;
                case ComponentInfo::rom: sResult = L"rom"; SetConsoleTextAttribute(hStdConsole, 27); break;
                case ComponentInfo::UNKNOWN:
                default:  sResult = L"Unknown"; SetConsoleTextAttribute(hStdConsole, 24); break;
                }
                std::wcout << fd.path().filename().wstring() << L" [" << sResult << L"]" << std::endl;
            }
        }
    } catch (...) {
        SetConsoleTextAttribute(hStdConsole, 28);
        std::wcerr << "Unexpected exception" << std::endl;
        SetConsoleTextAttribute(hStdConsole, 7);
        return -1;
    }

    SetConsoleTextAttribute(hStdConsole, 7);

    return 0;
}
