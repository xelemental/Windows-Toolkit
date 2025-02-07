#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

void ListProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    
    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot!" << std::endl;
        return;
    }

    // Initialize PROCESSENTRY32 structure
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Failed to get first process!" << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    // Print process list
    std::cout << "Process ID\tProcess Name" << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    do {
        std::wcout << pe32.th32ProcessID << "\t\t" << pe32.szExeFile << std::endl;
    } while (Process32Next(hProcessSnap, &pe32));

    // Close the snapshot handle
    CloseHandle(hProcessSnap);
}

int main() {
    ListProcesses();
    return 0;
}
