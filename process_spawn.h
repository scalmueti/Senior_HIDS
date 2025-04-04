#ifndef PROCESS_SPAWN_H
#define PROCESS_SPAWN_H

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>

void detectParentChildProcesses();
bool isSuspiciousChild(const std::wstring& childProcName);

#endif