#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    
    AllocConsole();

    
    FILE* consoleOutput;
    if (freopen_s(&consoleOutput, "CONOUT$", "w", stdout) != 0) {
        MessageBox(NULL, L"Failed to redirect standard output to console window", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

  
    PROCESSENTRY32 pe{};
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

    do {
        if (lstrcmpi(pe.szExeFile, TEXT("Teams.exe")) == 0) {
            wcout << "Found process " << pe.szExeFile << " with PID " << pe.th32ProcessID << endl;

            THREADENTRY32 te{};
            ZeroMemory(&te, sizeof(te));
            te.dwSize = sizeof(THREADENTRY32);



            if (Thread32First(snapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == pe.th32ProcessID) {
                        wcout << "    Found thread with ID " << te.th32ThreadID << endl;
                    }
                } while (Thread32Next(snapshot, &te));
            }
            else {
                wcout << "Failed to get first thread in snapshot" << endl;
            }

            CloseHandle(snapshot);
        }
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);

    
    system("PAUSE");

    
    fclose(consoleOutput);
    FreeConsole();
    return 0;
}
