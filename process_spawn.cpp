#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

// Check if the child process is suspicious
bool isSuspiciousChild(const std::string& childProcName) {
    std::vector<std::string> suspicious = { "powershell.exe", "cmd.exe", "wscript.exe" };
    for (const auto& s : suspicious) {
        if (childProcName == s)
            return true;
    }
    return false;
}

void detectParentChildProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot.\n";
        return;
    }

    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process)) {
        std::cerr << "Failed to get first process.\n";
        CloseHandle(snapshot);
        return;
    }

    std::vector<PROCESSENTRY32> processList;

    do {
        processList.push_back(process);
    } while (Process32Next(snapshot, &process));

    for (const auto& child : processList) {
        for (const auto& parent : processList) {
            if (child.th32ParentProcessID == parent.th32ProcessID) {
                if (isSuspiciousChild(child.szExeFile)) {
                    std::cout << "Suspicious child process detected: " << child.szExeFile
                              << " spawned by " << parent.szExeFile << std::endl;
                }
            }
        }
    }

    CloseHandle(snapshot);
}
