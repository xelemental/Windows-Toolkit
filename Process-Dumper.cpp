//Dump Process Memory using MiniDumpWriteDump
//Author : ElementalX

#include <iostream>
#include <Windows.h>
#include<minidumpapiset.h>
#include<DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")

using namespace std;




int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR strCmdLine, int nCmdShow)
{


	//Open the target process which is to be dumped

	cout << " Welcome to Process Dumper......." << endl;
	DWORD pid;
	cout << "Please enter the process which you want to dump : " << endl;
	cin >> pid;

	HANDLE _OpenProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , NULL, pid);
	if (_OpenProcess) {

		cout << "The process was succesfully opened :)))" << endl;

	}
	else {


		cout << "The process was not opened :((((" << endl;


	}

	

	//Create a file in which the dumped contents are to be written

	HANDLE _CreateFile = CreateFile(L"C:\\Users\\process-contents.dmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);


	//Dump the contents of the process inside MiniDumpWrite 

	MINIDUMP_EXCEPTION_INFORMATION mei;
	ZeroMemory(&mei, sizeof(mei));
	MINIDUMP_CALLBACK_INFORMATION mci;
	ZeroMemory(&mci, sizeof(mci));

	BOOL _Dumped = MiniDumpWriteDump(_OpenProcess, pid, _CreateFile, (MINIDUMP_TYPE)0x00000002, &mei, NULL, &mci);

	if (_Dumped == TRUE)
	{

		cout << " The token contents have been dumped :-)" << endl;


	}

	else {

		cout << "Failed to dump the process of the memory" << endl;


	}




	return 0;


}
