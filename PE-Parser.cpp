#include <iostream>

#include <Windows.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
  //Opening the file we want to parse

  HANDLE _CreateFile = CreateFile(L "C:\\Users\\add_your_own_exe.exe", GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (_CreateFile == INVALID_HANDLE_VALUE) {

    printf("Could not read file");

  }

  //Get the file size 
  DWORD dwFileSize = GetFileSize(_CreateFile, NULL);

  //Create a file mapping 
  HANDLE _CreateFileMapping = CreateFileMappingA(_CreateFile, NULL, PAGE_READONLY, 0, dwFileSize, NULL);

  if (_CreateFileMapping == NULL) {

    printf("Failed to create file mapping");
  }

  //Create Mapview of the base address

  LPVOID lpBaseAddressa = MapViewOfFile(_CreateFileMapping, FILE_MAP_READ, 0, 0, 0);

  if (lpBaseAddressa == NULL) {

    printf("Failed to map the file ");
  }

  //Declare the DOS_HEADER
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER) lpBaseAddressa;

  if (dos_header -> e_magic == 23117) {

    cout << " It has a valid DOS header : " << endl;
    //Prints the values of the structure in decimal value 

    cout << "The value of e_magic is : " << hex << dos_header -> e_magic << endl;
    cout << "The value of e_cblp is : " << hex << dos_header -> e_cblp << endl;
    cout << "The value of e_cp is : " << hex << dos_header -> e_cp << endl;
    cout << "The value of e_crlc is : " << hex << dos_header -> e_crlc << endl;
    cout << "The value of e_cparhdr is : " << hex << dos_header -> e_cparhdr << endl;
    cout << "The value of e_minalloc is : " << hex << dos_header -> e_minalloc << endl;
    cout << "The value of e_maxalloc is : " << hex << dos_header -> e_maxalloc << endl;
    cout << "The value of e_ss is : " << hex << dos_header -> e_ss << endl;
    cout << "The value of e_sp is : " << hex << dos_header -> e_sp << endl;
    cout << "The value of e_csum is : " << hex << dos_header -> e_csum << endl;
    cout << "The value of e_ip is : " << hex << dos_header -> e_ip << endl;
    cout << "The value of e_cs is : " << hex << dos_header -> e_cs << endl;
    cout << "The value of e_lfarlc is : " << hex << dos_header -> e_lfarlc << endl;
    cout << "The value of e_ovno is : " << hex << dos_header -> e_ovno << endl;
    cout << "The value of e_res[4] is : " << hex << dos_header -> e_res[0] << " " << hex << dos_header -> e_res[1] << " " << hex << dos_header -> e_res[2] << " " << hex << dos_header -> e_res[3] << endl;
    cout << "The value of e_oemid is : " << hex << dos_header -> e_oemid << endl;
    cout << "The value of e_oeminfo is : " << hex << dos_header -> e_oeminfo << endl;
    cout << "The value of e_res2[10] is : " << hex << dos_header -> e_res2[0] << " " << hex << dos_header -> e_res2[1] << " " << hex << dos_header -> e_res2[2] << " " << hex << dos_header -> e_res2[3] << " " << hex << dos_header -> e_res2[4] << " " << hex << dos_header -> e_res2[5] << " " << hex << dos_header -> e_res2[6] << " " << hex << dos_header -> e_res2[7] << " " << hex << dos_header -> e_res2[8] << " " << hex << dos_header -> e_res2[9] << endl;
    cout << "The value of e_lfanew is : " << hex << dos_header -> e_lfanew << endl;

  }
  //Declaring DOS Stub

  char * dos_stub = (char * ) dos_header + sizeof(IMAGE_DOS_HEADER);

  // Print the contents of the DOS Stub by substracting the address of new PE header from the size of DOS-Header
  cout << "DOS Stub: " << endl;
  for (int i = 0; i < dos_header -> e_lfanew - sizeof(IMAGE_DOS_HEADER); i++) {
    printf("%02X ", (unsigned char) dos_stub[i]);
  }
  cout << endl;

  //Declaring RICH Header Structure 

  typedef struct _RICHHEADER {
    DWORD dwKey;
    DWORD dwVersion;
    DWORD dwProductVersion;
    DWORD dwFileVersion;
    DWORD dwNumberOfIds;
    DWORD dwReserved;
    struct {
      DWORD id;
      DWORD cnt;
      DWORD ofs;
    }
    richId[1];
  }
  RICHHEADER, * PRICHHEADER;

  PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE) dos_header + dos_header -> e_lfanew);
  PRICHHEADER rich_header = (PRICHHEADER)((LPBYTE) nt_headers + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers -> FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
  cout << "RICH Header:" << endl;
  cout << "  Rich Key: " << hex << rich_header -> dwKey << endl;
  cout << "  Rich Version: " << dec << rich_header -> dwVersion << endl;
  cout << "  Rich Product Version: " << dec << rich_header -> dwProductVersion << endl;
  cout << "  Rich File Version: " << dec << rich_header -> dwFileVersion << endl;
  cout << "  Rich Number of IDs: " << dec << rich_header -> dwNumberOfIds << endl;

  // Declaring  the IMAGE_NT_HEADER Structure

  PIMAGE_NT_HEADERS64 ntheader = (PIMAGE_NT_HEADERS64)((PBYTE) lpBaseAddressa + dos_header -> e_lfanew);

  //Checking the Valid Signature

  if (ntheader -> Signature != IMAGE_NT_SIGNATURE) {
    printf("Invalid PE file");
  }

  //  Declaring  the IMAGE_FILE_HEADER structure

  IMAGE_FILE_HEADER file_header = ntheader -> FileHeader;

  //Parsing the IMAGE_FILE_HEADER structure

  printf("Number of sections: %u\n", file_header.NumberOfSections);
  printf("Timestamp: %u\n", file_header.TimeDateStamp);
  printf("Machine :  %u\n", file_header.Machine);
  cout << " The pointer to symbols : " << file_header.PointerToSymbolTable;
  cout << " The Number of symbols " << file_header.NumberOfSymbols;

  //  Declaring  the  IMAGE_OPTIONAL_HEADER64 structure

  IMAGE_OPTIONAL_HEADER64 optional_header = ntheader -> OptionalHeader;
  IMAGE_OPTIONAL_HEADER optional_header32 = ntheader -> OptionalHeader;

  //Declaring the Data directory structure to use it 
  IMAGE_DATA_DIRECTORY export_table_directory = optional_header.DataDirectory[0];
  IMAGE_DATA_DIRECTORY import_table_directory = optional_header.DataDirectory[1];

  if (optional_header.Magic == 0x20) {
    //Parsing the IMAGE_OPTIONAL_HEADER64 for 64 bit PE Files  

    cout << " The magic number is : " << optional_header.Magic << endl;
    cout << " The Major Linker version is : " << optional_header.MajorLinkerVersion << endl;
    cout << " The Minor Linker version is : " << optional_header.MinorLinkerVersion << endl;
    cout << " The size of .text section is : " << optional_header.SizeOfCode << endl;
    cout << " The size of initialized data is : " << optional_header.SizeOfInitializedData << endl;
    cout << " The size of the uninitialized data : " << optional_header.SizeOfUninitializedData << endl;
    cout << " The Address of the Entrypoint is : " << optional_header.AddressOfEntryPoint << endl;
    cout << " The Image Base is : " << optional_header.ImageBase << endl;
    cout << " The Address Of Entrypoint for the .text section " << optional_header.BaseOfCode << endl;
    //	cout << " The Address of Entrypoint for the .data section : " << optional_header.BaseOfData << endl; FOR 32-BIT FILES
    cout << " The Image Base for this PE Image is : " << optional_header.ImageBase << endl;
    cout << " The Size of Headers is : " << optional_header.SizeOfHeaders << endl;
    cout << " The DLL Characteristics are : " << optional_header.DllCharacteristics << endl;
    cout << " The Subsystem required to run this image file : " << optional_header.Subsystem << endl;

  }

  //To-do  : Data Directories, Sections, IAT, EAT , Reloc. 
  
  
  system("PAUSE");
  return 0;
  UnmapViewOfFile(lpBaseAddressa);
  CloseHandle(_CreateFile);

  return 0;

}
