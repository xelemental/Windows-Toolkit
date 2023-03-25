//Add an empty PE section with for adding executable code.

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>


#define IMAGE_NEXT_SECTION(p) ((PIMAGE_SECTION_HEADER)((DWORD_PTR)(p) + sizeof(IMAGE_SECTION_HEADER)))

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{


    // Open the executable image
    HANDLE hFile = CreateFileW(L"C:\\Users\\yourfile.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open image file. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    // Create a file mapping
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == NULL) {
        std::cout << "Failed to create file mapping. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
      //  CloseHandle(hProcess);
        return 1;
    }

    // Map the file into memory
    LPVOID lpFileBase = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpFileBase == NULL) {
        std::cout << "Failed to map file into memory. Error: " << GetLastError() << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
      //  CloseHandle(hProcess);
        return 1;
    }

    //Get the base address and the size of the PE file
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    DWORD_PTR dwImageBase = pNtHeader->OptionalHeader.ImageBase;
    DWORD_PTR dwImageSize = pNtHeader->OptionalHeader.SizeOfImage;

    // Locate the last section in the PE file
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections - 1; i++) {
        pSectionHeader = IMAGE_NEXT_SECTION(pSectionHeader);
    }

    // Calculate the new section header
    DWORD_PTR dwNewSectionAddress = ((DWORD_PTR)pSectionHeader + sizeof(IMAGE_SECTION_HEADER));
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)dwNewSectionAddress;
    ZeroMemory(pNewSectionHeader, sizeof(IMAGE_SECTION_HEADER));

    // Set the new section name, attributes, and size
    memcpy(pNewSectionHeader->Name, "._rsrc", 8); //You can add your own section names.
    pNewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    pNewSectionHeader->Misc.VirtualSize = 0x1000;
    pNewSectionHeader->SizeOfRawData = 0x2000;
    pNewSectionHeader->VirtualAddress = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;
    pNewSectionHeader->PointerToRawData = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;
    pNewSectionHeader->NumberOfLinenumbers = 0;
    pNewSectionHeader->NumberOfRelocations = 0;
    pNewSectionHeader->PointerToLinenumbers = 0;
    pNewSectionHeader->PointerToRelocations = 0;

    // Update the section headers in the PE file
    pNtHeader->FileHeader.NumberOfSections++;
    pNtHeader->OptionalHeader.SizeOfImage += pNewSectionHeader->Misc.VirtualSize;

    // Unmap the file from memory
    UnmapViewOfFile(lpFileBase);

    // Close the file mapping and the file handle
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // Close the process handle
    //CloseHandle(hProcess);

    std::cout << "New section added to PE file" << std::endl;
    return 0;
}
