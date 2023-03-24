// DLL Injection using CreateRemoteThread() 

#include <Windows.h>
#include <iostream>
#include <WinBase.h>



using namespace std;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
   AllocConsole();
  
   FILE* consoleOutput;
   if (freopen_s(&consoleOutput, "CONOUT$", "w", stdout) != 0) {
       MessageBox(NULL, L"Failed to redirect standard output to console window", L"Error", MB_OK | MB_ICONERROR);
       return 1;
   }

    // Opening a target process
    wcout << "Hi! Welcome to the DLL Injector!" << endl;

    DWORD process_id;
    wcout << "Please enter the process ID inside whom you want to inject the target DLL: " << endl;
    wcin >> process_id;
    wcin.ignore();

    LPVOID dll_to_inject;
    wchar_t dll_path[] = L"C:\\Users\\user_demo.dll"; //Replace the path of your DLL
    dll_to_inject = (LPVOID)dll_path;

    HANDLE _OpenProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, process_id);
    if (_OpenProcess == NULL) {
        system("PAUSE");
        wcout << "Failed to open process with proper access masks" << endl;
        return 1;
    }

    // Allocating buffer after opening the target process above
    void* allocated_memory = VirtualAllocEx(_OpenProcess, NULL, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // This is returning the buffer allocated address
    if (!allocated_memory) {
        system("PAUSE");
        wcout << "The buffer allocation failed" << endl;
        CloseHandle(_OpenProcess);
        return 1;
    }

    // Now, need to add the DLL inside the allocated buffer returned by VirtualAllocEx
    BOOL _WriteProcessMemory = WriteProcessMemory(_OpenProcess, allocated_memory, dll_to_inject, (::wcslen((const wchar_t*)dll_to_inject) + 1) * sizeof(wchar_t), NULL);
    if (!_WriteProcessMemory) {
        wcout << "Failed to write process" << endl;
        VirtualFreeEx(_OpenProcess, allocated_memory, 0, MEM_RELEASE);
        CloseHandle(_OpenProcess);
        return 1;
    }

    // Create the thread inside the target process
    DWORD tid;
    HANDLE hThread = CreateRemoteThread(_OpenProcess, NULL, 0, (LPTHREAD_START_ROUTINE)::GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"), allocated_memory, 0, &tid);
    if (!hThread) {
        wcout << "Failed to create the remote thread" << endl;
        VirtualFreeEx(_OpenProcess, allocated_memory, 0, MEM_RELEASE);
        CloseHandle(_OpenProcess);
        return 1;
    }

    wcout << "Thread " << tid << " created successfully!" << endl;
    if (WAIT_OBJECT_0 == ::WaitForSingleObject(hThread, 5000)) {
        wcout << "Thread exited." << endl;
    }
    else {
        wcout << "Thread still hanging around..." << endl;
    }

    VirtualFreeEx(_OpenProcess, allocated_memory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(_OpenProcess);

   fclose(consoleOutput);
   FreeConsole();

    return 0;
}
