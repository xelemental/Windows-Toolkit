#include <iostream>
#include <Windows.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

using namespace std;



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//Opening the file we want to parse

	wcout << "Hi! Please Enter the path to PE File : " << endl;
	wstring wfilename;
	wcin >> wfilename;

	string filename(wfilename.begin(), wfilename.end()); // Convert wide string to narrow string
	LPCSTR lpFileName = filename.c_str();

	HANDLE _CreateFile = CreateFileA(lpFileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)lpBaseAddressa;

	if (dos_header->e_magic == 23117) {

		cout << " It has a valid DOS header : " << endl;
		//Prints the values of the structure in decimal value 

		cout << "The value of e_magic is : " << hex << dos_header->e_magic << endl;
		cout << "The value of e_cblp is : " << hex << dos_header->e_cblp << endl;
		cout << "The value of e_cp is : " << hex << dos_header->e_cp << endl;
		cout << "The value of e_crlc is : " << hex << dos_header->e_crlc << endl;
		cout << "The value of e_cparhdr is : " << hex << dos_header->e_cparhdr << endl;
		cout << "The value of e_minalloc is : " << hex << dos_header->e_minalloc << endl;
		cout << "The value of e_maxalloc is : " << hex << dos_header->e_maxalloc << endl;
		cout << "The value of e_ss is : " << hex << dos_header->e_ss << endl;
		cout << "The value of e_sp is : " << hex << dos_header->e_sp << endl;
		cout << "The value of e_csum is : " << hex << dos_header->e_csum << endl;
		cout << "The value of e_ip is : " << hex << dos_header->e_ip << endl;
		cout << "The value of e_cs is : " << hex << dos_header->e_cs << endl;
		cout << "The value of e_lfarlc is : " << hex << dos_header->e_lfarlc << endl;
		cout << "The value of e_ovno is : " << hex << dos_header->e_ovno << endl;
		cout << "The value of e_res[4] is : " << hex << dos_header->e_res[0] << " " << hex << dos_header->e_res[1] << " " << hex << dos_header->e_res[2] << " " << hex << dos_header->e_res[3] << endl;
		cout << "The value of e_oemid is : " << hex << dos_header->e_oemid << endl;
		cout << "The value of e_oeminfo is : " << hex << dos_header->e_oeminfo << endl;
		cout << "The value of e_res2[10] is : " << hex << dos_header->e_res2[0] << " " << hex << dos_header->e_res2[1] << " " << hex << dos_header->e_res2[2] << " " << hex << dos_header->e_res2[3] << " " << hex << dos_header->e_res2[4] << " " << hex << dos_header->e_res2[5] << " " << hex << dos_header->e_res2[6] << " " << hex << dos_header->e_res2[7] << " " << hex << dos_header->e_res2[8] << " " << hex << dos_header->e_res2[9] << endl;
		cout << "The value of e_lfanew is : " << hex << dos_header->e_lfanew << endl;

	}
	//Declaring DOS Stub

	char* dos_stub = (char*)dos_header + sizeof(IMAGE_DOS_HEADER); 

	// Print the contents of the DOS Stub by substracting the address of new PE header from the size of DOS-Header
	cout << "DOS Stub: " << endl;
	for (int i = 0; i < dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER); i++)
	{
		printf("%02X ", (unsigned char)dos_stub[i]);
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
		} richId[1];
	} RICHHEADER, * PRICHHEADER;


	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dos_header + dos_header->e_lfanew);
	PRICHHEADER rich_header = (PRICHHEADER)((LPBYTE)nt_headers + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
	cout << "RICH Header:" << endl;
	cout << "  Rich Key: " << hex << rich_header->dwKey << endl;
	cout << "  Rich Version: " << dec << rich_header->dwVersion << endl;
	cout << "  Rich Product Version: " << dec << rich_header->dwProductVersion << endl;
	cout << "  Rich File Version: " << dec << rich_header->dwFileVersion << endl;
	cout << "  Rich Number of IDs: " << dec << rich_header->dwNumberOfIds << endl;



	// Declaring  the IMAGE_NT_HEADER Structure


	PIMAGE_NT_HEADERS64 ntheader = (PIMAGE_NT_HEADERS64)((PBYTE)lpBaseAddressa + dos_header->e_lfanew);

	//Checking the Valid Signature

	if (ntheader->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid PE file");
	}

	//  Declaring  the IMAGE_FILE_HEADER structure

	IMAGE_FILE_HEADER file_header = ntheader->FileHeader;

	//Parsing the IMAGE_FILE_HEADER structure


	printf("Number of sections: %u\n", file_header.NumberOfSections);
	printf("Timestamp: %u\n", file_header.TimeDateStamp);
	printf("Machine :  %u\n", file_header.Machine);
	cout << " The pointer to symbols : " <<  file_header.PointerToSymbolTable;
	cout << " The Number of symbols " << file_header.NumberOfSymbols;

	//  Declaring  the  IMAGE_OPTIONAL_HEADER64 structure

	IMAGE_OPTIONAL_HEADER64 optional_header = ntheader->OptionalHeader;
	IMAGE_OPTIONAL_HEADER optional_header32 = ntheader->OptionalHeader;


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
	
	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", ntheader->OptionalHeader.DataDirectory[0].VirtualAddress, ntheader->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", ntheader->OptionalHeader.DataDirectory[1].VirtualAddress, ntheader->OptionalHeader.DataDirectory[1].Size);
	printf("\tResource Directory Address: 0x%x; Size: 0x%x\n", ntheader->OptionalHeader.DataDirectory[1].VirtualAddress, ntheader->OptionalHeader.DataDirectory[2].Size);
	printf("\tImport Address Table : 0x%x; Size: 0x%x\n", ntheader->OptionalHeader.DataDirectory[1].VirtualAddress, ntheader->OptionalHeader.DataDirectory[12].Size);
	printf("\tDebug Directory Address: 0x%x; Size: 0x%x\n", ntheader->OptionalHeader.DataDirectory[1].VirtualAddress, ntheader->OptionalHeader.DataDirectory[6].Size);


	//DEFINING SECTION HEADER structure

	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((PBYTE)ntheader + sizeof(IMAGE_NT_HEADERS64)); //Here we defined the section header
	
	//Then we went back to the number of sections from the File Header structure and used that to loop over all and print the names

	int i{};
	for (i = 0; i < file_header.NumberOfSections; i++)  
	{
		//Printing the section attributes

		wcout << section_header->Name << endl;
		wcout << section_header->Misc.PhysicalAddress << endl;
		wcout << section_header->Misc.VirtualSize << endl;
		wcout << section_header->VirtualAddress << endl;
		wcout << section_header->PointerToRawData << endl;
		wcout << section_header->PointerToRelocations << endl;
		wcout << section_header->PointerToLinenumbers << endl;
		wcout << section_header->NumberOfRelocations << endl;
		wcout << section_header->NumberOfLinenumbers << endl;
		wcout << section_header->Characteristics << endl;

		//Check if the section name is .idata

		if (strncmp((char*)section_header->Name, ".idata", IMAGE_SIZEOF_SHORT_NAME) == 0)
		{

			DWORD import_table_va = section_header->VirtualAddress;  //Calculate virtual address off the section and store in a variable
			PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ntheader + import_table_va); //Declare the IMAGE IMPORT DESCRIPTOR

			while (import_table->Name != 0)
			{
				// Get the name of the DLL
				char* dll_name = (char*)((PBYTE)ntheader + import_table->Name);
				wcout << "\tDLL name: " << dll_name << endl;
				PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)ntheader + import_table->FirstThunk);

				// Loop through each imported function in this DLL
				while (thunk->u1.AddressOfData != 0)
				{
					// Check if this import is by ordinal or by name
					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						// Imported by ordinal
						wcout << "\t\tFunction imported by ordinal: " << dec << (thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG) << endl;
					}
					else
					{
						// Imported by name
						PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((PBYTE)ntheader + thunk->u1.AddressOfData);
						wcout << "\t\tFunction name: " << import_by_name->Name << endl;
					}

					// Move to the next imported function
					thunk++;
				}

				// Move to the next import descriptor
				import_table++;
			}
		}

		// Move to the next section
		section_header++;

	}


	//https://sabotagesec.com/pe-relocation-table/ - PE Relocation table 
    //https://nekobin.com/vayaxuledi - PE Relocation 

	// Find the relocation table section
	PIMAGE_SECTION_HEADER reloc_section = NULL;
	for (i = 0; i < file_header.NumberOfSections; i++)
	{
		if (strncmp((char*)section_header->Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			reloc_section = section_header;
			break;
		}
		section_header++;
	}


	DWORD preferred_load_address = optional_header.ImageBase; // The preferred load address from the optional header
	DWORD actual_load_address = section_header->VirtualAddress; // The actual load address from the section header
	int delta = actual_load_address - preferred_load_address; // Calculate the delta
	DWORD new_imagebase = preferred_load_address + delta; // Calculate the new image base

	// If the relocation section is found, process it
	if (reloc_section != NULL)
	{
		DWORD reloc_table_va = reloc_section->VirtualAddress;
		PIMAGE_BASE_RELOCATION reloc_block = (PIMAGE_BASE_RELOCATION)((PBYTE)ntheader + reloc_table_va);

		while (reloc_block->VirtualAddress != 0)
		{
			DWORD block_size = reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
			WORD* reloc_entry = (WORD*)((PBYTE)reloc_block + sizeof(IMAGE_BASE_RELOCATION));

			// Iterate through all relocation entries in this block
			while (block_size > 0)
			{
				DWORD offset = (*reloc_entry & 0xFFF);
				WORD type = (*reloc_entry >> 12);

				// Calculate the new address based on the delta
				DWORD old_address = reloc_block->VirtualAddress + offset;
				DWORD new_address = old_address + delta;

				// Print the information about the relocation entry
				wcout << "\t\tType: " << dec << type << endl;
				wcout << "\t\tOld address: 0x" << hex << old_address << endl;
				wcout << "\t\tNew address: 0x" << hex << new_address << endl;

				// Move to the next relocation entry
				reloc_entry++;
				block_size -= sizeof(WORD);
			}

			// Move to the next relocation block
			reloc_block = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc_block + reloc_block->SizeOfBlock);
		}
	}
	else
	{
		wcout << "Relocation section not found" << endl;
	}

	wcout << "Done Parsing the PE File ";
	return 0;
	UnmapViewOfFile(lpBaseAddressa);
    CloseHandle(_CreateFile); 

	return 0;


}
