//Author : ElementalX (Subhajeet) 
//An approach to detect Unloaded DLLs using MinidumpWriteDumpAPI.

#include <Windows.h>
#include <iostream>
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")

using namespace std;



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{


	wcout << "Welcome to D-Dump : " << endl;
	wcout << "Please enter the specific windows process, you are suspecting :  " << endl;
	DWORD processID ;
	wcin >> processID;
	HANDLE _OpenProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL, processID);
	if (_OpenProcess) {


		cout << "The handle to the suspected malicious process has been acquired ..." << endl;



	}
	else {

		wcout << " Failed to Open the process ...." << endl;
	}

	//Create a file in which the dumped contents are to be written

	HANDLE _CreateFile = CreateFile(L"C:\\Users\\\process-contents.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);



	//Using MinidumpWriteDump to dump the unloaded DLLs

	MINIDUMP_EXCEPTION_INFORMATION mei;
	ZeroMemory(&mei, sizeof(mei));
	MINIDUMP_CALLBACK_INFORMATION mci;
	ZeroMemory(&mci, sizeof(mci));

	BOOL DLL_Dumped = MiniDumpWriteDump(_OpenProcess, processID, _CreateFile, (MINIDUMP_TYPE)0x00000020, &mei, NULL, &mci);

	if (DLL_Dumped) {

		cout << " The process's unloaded DLLS are dumped " << endl;

	}
	else {

		cout << "Dumping Failed " << endl; 
	}







	return 0; 







}
