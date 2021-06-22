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
#include <io.h>
#include <fcntl.h>
#include <algorithm>

#define COLOR_ERROR     12
#define COLOR_DEFAULT   7
#define COLOR_ANYCPU    15
#define COLOR_X86       14
#define COLOR_X64       10
#define COLOR_ROM       11
#define COLOR_UNKNOWN   8

void setErrorColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_ERROR_HANDLE), color);
}

void setConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

enum class ComponentInfo {
    UNKNOWN,
    ANYCPU,
    X86,
    x64,
    rom
};

int64_t rva_to_offset(const IMAGE_SECTION_HEADER *sections, int num_sections, DWORD rva)
{
    for (int i = 0; i < num_sections; i++) {
        if (sections[i].VirtualAddress <= rva && sections[i].VirtualAddress + sections[i].SizeOfRawData > rva) {
            return sections[i].PointerToRawData + rva - sections[i].VirtualAddress;
        }
    }
    return 0;
}

ComponentInfo GetArchitectureInfo(const std::filesystem::path & path) {

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

void PrintFileInfo(const std::filesystem::path & fspath)
{

    std::wstring sResult;
    switch (GetArchitectureInfo(fspath))
    {
    case ComponentInfo::ANYCPU: sResult = L"AnyCpu";  setConsoleColor(COLOR_ANYCPU);  break;
    case ComponentInfo::X86:    sResult = L"x86";     setConsoleColor(COLOR_X86);     break;
    case ComponentInfo::x64:    sResult = L"x64";     setConsoleColor(COLOR_X64);     break;
    case ComponentInfo::rom:    sResult = L"rom";     setConsoleColor(COLOR_ROM);     break;
    case ComponentInfo::UNKNOWN:
    default:                    sResult = L"Unknown"; setConsoleColor(COLOR_UNKNOWN); break;
    }
    std::wcout << fspath.filename() << L" [" << sResult << L"]" << std::endl;
    setConsoleColor(COLOR_DEFAULT);
}

int wmain(int argc, wchar_t *argv[])
{
    /* 
    for(WORD ind = 1; ind < 255; ind++) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ind);
        std::cout << ind << " test console color  " << std::endl;
    }
    */
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    std::filesystem::path path;

    if (argc > 2) {
        setErrorColor(COLOR_ERROR);
        std::wcerr << L"Usage: " << argv[0] << L" \"path to folder or file\"" << std::endl;
        setErrorColor(COLOR_DEFAULT);
        return 1;
    } else if(argc == 2) {
        path = argv[1];
    } else {
        path = std::filesystem::current_path();
    }

    if (std::filesystem::is_regular_file(path)) {
        PrintFileInfo(path);
        return 2;
    }

    if (!std::filesystem::is_directory(path))
    {
        setErrorColor(COLOR_ERROR);
        std::wcerr << L"Error: The path is not file or directory, or access denied!\n[" << path << L"]" << std::endl;
        setErrorColor(COLOR_DEFAULT);
        return 3;
    }

    try {
        if (std::filesystem::exists(path)) {
            for (const auto & fd : std::filesystem::directory_iterator(path)) {
                std::wstring itemExtension = fd.path().extension();
                std::transform(itemExtension.begin(), itemExtension.end(), itemExtension.begin(), ::tolower);
                if(!(itemExtension == L".dll" || itemExtension == L".exe"))
                    continue;
                PrintFileInfo(fd.path());
            }
        }
    } catch (const std::exception& ex) {
        setErrorColor(COLOR_ERROR);
        std::wcerr << L"Error: " << ex.what() << std::endl;
        setErrorColor(COLOR_DEFAULT);
        return 4;
    } catch (...) {
        setErrorColor(COLOR_ERROR);
        std::wcerr << L"Unexpected exception" << std::endl;
        setErrorColor(COLOR_DEFAULT);
        return 5;
    }

    return 0;
}
