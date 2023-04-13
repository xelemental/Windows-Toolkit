#include <iostream>
#include <Windows.h>
#include <string.h>


using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{


	LPSYSTEM_INFO lpsi = (LPSYSTEM_INFO)malloc(sizeof(SYSTEM_INFO));
	GetNativeSystemInfo(lpsi);
	wcout << lpsi->dwNumberOfProcessors << endl;
	char lpBuffer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD nSize = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameA(lpBuffer, &nSize);
	char _lpBuffer[MAX_PATH + 1];
	UINT uSize = MAX_PATH;
	GetWindowsDirectoryA(_lpBuffer, uSize);
	system("PAUSE");

	return 0;

}
