#include <windows.h>
#include <windowsx.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <cassert>
#include <strsafe.h>
#include "../hackKit/hackKit.h"

void version(void)
{
    puts("PayLordz injector Version 0.7 by katahiromz");
    puts("Copyright (C) 2022 Katayama Hirofumi MZ");
    puts("License: MIT");
}

void usage(void)
{
    CHAR szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, _countof(szPath));
    PathRemoveExtensionA(szPath);
    LPCSTR filename = PathFindFileNameA(szPath);

    printf("%s -- PayLordz injector\n", filename);
    printf("\n");
    printf("Usage: %s [Options]\n");
    printf("Options:\n");
    printf("  --inject PID               Do inject the process of PID.\n");
    printf("  --uninject PID             Do un-inject the process of PID.\n");
    printf("  --payload \"PAYLOAD.DLL\"    Specify the payload to inject (multiple OK).\n");
    printf("  --param \"PARAMETER\"        Specify the parameter string (Not supported yet).\n");
    printf("  --run your_app.exe ...     Specify the command line to run and inject.\n");
    printf("  --help                     Show this message.\n");
    printf("  --version                  Show the version info.\n");
}

enum RET
{
    RET_OK = 0,
    RET_INVALID_ARG = 1,
    RET_INVALID_PAYLOAD = 2,
    RET_BITS_MISMATCH_PROCESS = 3,
    RET_BITS_MISMATCH_PAYLOAD = 4,
    RET_BITS_MISMATCH_EXE = 5,
    RET_CANNOT_RUN = 6,
    RET_CANNOT_INJECT = 7,
    RET_CANNOT_UNINJECT = 8,
    RET_LOGICAL_ERROR = 9,
    RET_INVALID_EXE = 10,
};

enum ACTION
{
    ACTION_NONE = 0,
    ACTION_INJECT = 1,
    ACTION_UNINJECT = 2,
    ACTION_RUN = 3,
};

RET action_inject(std::vector<std::wstring>& payloads, DWORD pid, LPCWSTR param)
{
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        LPCWSTR payload = payloads[i].c_str();
        WCHAR szPayload[MAX_PATH];
        if (!SearchPathW(NULL, payload, L".dll", _countof(szPayload), szPayload, NULL) ||
            !doInjectDll(szPayload, pid))
        {
            fprintf(stderr, "ERROR: Unable to inject payload '%ls'.\n", payload);
            return RET_CANNOT_INJECT;
        }
    }
    fprintf(stderr, "SUCCESS.\n");
    return RET_OK;
}

RET action_uninject(std::vector<std::wstring>& payloads, DWORD pid, LPCWSTR param)
{
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        LPCWSTR payload = payloads[i].c_str();
        WCHAR szPayload[MAX_PATH];
        if (!SearchPathW(NULL, payload, L".dll", _countof(szPayload), szPayload, NULL) ||
            !doUninjectDll(szPayload, pid))
        {
            fprintf(stderr, "ERROR: Unable to uninject payload '%ls'.\n", payload);
            return RET_CANNOT_UNINJECT;
        }
    }
    fprintf(stderr, "SUCCESS.\n");
    return RET_OK;
}

RET action_run(std::vector<std::wstring>& payloads, LPCWSTR exe_file, std::wstring& cmdline, LPCWSTR param)
{
    PROCESS_INFORMATION pi = { NULL };
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    BOOL ret = startProcess(cmdline.c_str(), si, pi, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL);
    if (!ret)
    {
        fprintf(stderr, "ERROR: Unable to run: %ls\n", cmdline.c_str());
        return RET_CANNOT_RUN;
    }

    DWORD pid = pi.dwProcessId;
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        LPCWSTR payload = payloads[i].c_str();
        WCHAR szPayload[MAX_PATH];
        if (!SearchPathW(NULL, payload, L".dll", _countof(szPayload), szPayload, NULL) ||
            !doInjectDll(szPayload, pid))
        {
            fprintf(stderr, "ERROR: Unable to inject payload '%ls'.\n", payload);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return RET_CANNOT_INJECT;
        }
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    fprintf(stderr, "SUCCESS.\n");
    return RET_OK;
}

RET check_payload(LPCWSTR payload)
{
    WCHAR szPayload[MAX_PATH];
    if (!SearchPathW(NULL, payload, L".dll", _countof(szPayload), szPayload, NULL))
    {
        fprintf(stderr, "ERROR: Payload '%ls' is invalid or not found.\n", payload);
        return RET_INVALID_PAYLOAD;
    }

    HINSTANCE hDLL = LoadLibraryExW(szPayload, NULL, LOAD_LIBRARY_AS_DATAFILE);
    FreeLibrary(hDLL);

    if (!PathFileExistsW(szPayload) || PathIsDirectoryW(szPayload) || !hDLL)
    {
        fprintf(stderr, "ERROR: Payload '%ls' is invalid or not found.\n", payload);
        return RET_INVALID_PAYLOAD;
    }

    WORD wPayloadMachine = getExeMachine(szPayload, TRUE);
#ifdef _WIN64
    if (wPayloadMachine != IMAGE_FILE_MACHINE_AMD64)
#else
    if (wPayloadMachine != IMAGE_FILE_MACHINE_I386)
#endif
    {
        fprintf(stderr, "ERROR: Bits mismatch of payload '%ls' (machine: 0x%04X)\n", szPayload, wPayloadMachine);
        return RET_BITS_MISMATCH_PAYLOAD;
    }

    return RET_OK;
}

RET do_it(ACTION action, DWORD pid, std::vector<std::wstring> payloads, LPCWSTR exe_file, std::wstring& cmdline, LPCWSTR param)
{
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        if (RET ret = check_payload(payloads[i].c_str()))
            return ret;
    }

#ifdef _WIN64
    if (pid && !isProcessIDWin64(pid))
#else
    if (pid && !isProcessIDWin32(pid))
#endif
    {
        fprintf(stderr, "ERROR: Bits mismatch of process\n");
        return RET_BITS_MISMATCH_PROCESS;
    }

    WCHAR szExeFile[MAX_PATH] = L"";
    if (exe_file)
    {
        SearchPathW(NULL, exe_file, L".exe", _countof(szExeFile), szExeFile, NULL);

        DWORD dwType = -1;
        if (!GetBinaryTypeW(szExeFile, &dwType))
        {
            fprintf(stderr, "ERROR: Executable '%ls' is invalid.\n", szExeFile);
            return RET_INVALID_EXE;
        }

        WORD wExeMachine = getExeMachine(szExeFile, FALSE);
#ifdef _WIN64
        if (wExeMachine != IMAGE_FILE_MACHINE_AMD64)
#else
        if (wExeMachine != IMAGE_FILE_MACHINE_I386)
#endif
        {
            fprintf(stderr, "ERROR: Bits mismatch of executable (machine: 0x%04X)\n", wExeMachine);
            return RET_BITS_MISMATCH_EXE;
        }
    }

    enableProcessPriviledge(SE_DEBUG_NAME);

    switch (action)
    {
    case ACTION_INJECT:
        return action_inject(payloads, pid, param);
    case ACTION_UNINJECT:
        return action_uninject(payloads, pid, param);
    case ACTION_RUN:
        return action_run(payloads, szExeFile, cmdline, param);
    default:
        fprintf(stderr, "ERROR: Logical error.\n");
        return RET_LOGICAL_ERROR;
    }
}

template <typename T_STR>
inline bool
mstr_replace_all(T_STR& str, const T_STR& from, const T_STR& to)
{
    bool ret = false;
    size_t i = 0;
    for (;;) {
        i = str.find(from, i);
        if (i == T_STR::npos)
            break;
        ret = true;
        str.replace(i, from.size(), to);
        i += to.size();
    }
    return ret;
}
template <typename T_STR>
inline bool
mstr_replace_all(T_STR& str,
                 const typename T_STR::value_type *from,
                 const typename T_STR::value_type *to)
{
    return mstr_replace_all(str, T_STR(from), T_STR(to));
}

std::wstring mstr_quote(const std::wstring& str)
{
    std::wstring ret = L"\"";
    ret += str;
    ret += L'\"';
    return ret;
}

int wmain(int argc, wchar_t **wargv)
{
    if (argc <= 1)
    {
        usage();
        return 0;
    }

    ACTION action = ACTION_NONE;
    DWORD pid = 0;
    LPCWSTR exe_file = NULL, param = NULL;
    std::vector<std::wstring> payloads;
    std::wstring cmdline;
    for (INT iarg = 1; iarg < argc; ++iarg)
    {
        LPCWSTR arg = wargv[iarg];
        if (action == ACTION_RUN)
        {
            if (cmdline.empty())
            {
                exe_file = arg;
            }
            else
            {
                cmdline += L" ";
            }
            if (wcschr(arg, L' ') || wcschr(arg, L'\t') || wcschr(arg, L'"'))
            {
                cmdline += mstr_quote(arg);
            }
            else
            {
                cmdline += arg;
            }
            continue;
        }
        if (lstrcmpiW(wargv[1], L"--help") == 0)
        {
            usage();
            return RET_OK;
        }
        if (lstrcmpiW(arg, L"--version") == 0)
        {
            version();
            return RET_OK;
        }
        if (lstrcmpiW(arg, L"--inject") == 0)
        {
            action = ACTION_INJECT;
            arg = wargv[++iarg];
            pid = wcstoul(arg, NULL, 0);
            continue;
        }
        if (lstrcmpiW(arg, L"--uninject") == 0)
        {
            action = ACTION_UNINJECT;
            arg = wargv[++iarg];
            pid = wcstoul(arg, NULL, 0);
            continue;
        }
        if (lstrcmpiW(arg, L"--payload") == 0)
        {
            payloads.push_back(wargv[++iarg]);
            continue;
        }
        if (lstrcmpiW(arg, L"--param") == 0)
        {
            param = wargv[++iarg];
            continue;
        }
        if (lstrcmpiW(arg, L"--run") == 0)
        {
            action = ACTION_RUN;
            continue;
        }

        fprintf(stderr, "ERROR: Invalid argument '%ls'.\n", arg);
        return RET_INVALID_ARG;
    }

    if (action == ACTION_NONE)
    {
        fprintf(stderr, "ERROR: Please specify either --inject, --uninject, or --run.\n");
        usage();
        return RET_INVALID_ARG;
    }

    if (payloads.empty())
    {
        fprintf(stderr, "ERROR: Please specify the payload.\n");
        usage();
        return RET_INVALID_ARG;
    }

    if (action == ACTION_RUN && cmdline.empty())
    {
        fprintf(stderr, "ERROR: Please specify the command line for --run.\n");
        usage();
        return RET_INVALID_ARG;
    }

    if ((action == ACTION_INJECT || action == ACTION_UNINJECT) && pid == 0)
    {
        fprintf(stderr, "ERROR: Please specify the process ID (pid).\n");
        usage();
        return RET_INVALID_ARG;
    }

    return do_it(action, pid, payloads, exe_file, cmdline, param);
}

int main(int argc, char **argv)
{
    INT myargc;
    LPWSTR *myargv = CommandLineToArgvW(GetCommandLineW(), &myargc);
    INT ret = wmain(myargc, myargv);
    LocalFree(myargv);
    return ret;
}
