#include "hackKit.h"
#include <psapi.h>
#include <shlwapi.h>
#include <imagehlp.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "imagehlp.lib")

BOOL isConsole(void)
{
    TCHAR szText[MAX_PATH];
    szText[0] = 0;
    return GetConsoleTitle(szText, _countof(szText));
}

static TCHAR s_logFile[MAX_PATH] = TEXT("");

void setLogFile(LPCTSTR filename)
{
    if (!filename || !filename[0])
    {
        s_logFile[0] = 0;
        return;
    }
    GetFullPathName(filename, _countof(s_logFile), s_logFile, NULL);
}

void LogA(LPCSTR fmt, ...)
{
    CHAR szText[512];
    va_list va;
    va_start(va, fmt);
    if (s_logFile[0])
    {
        if (FILE *fp = _tfopen(s_logFile, _T("a")))
        {
            vfprintf(fp, fmt, va);
            fclose(fp);
        }
    }
    else
    {
        StringCchVPrintfA(szText, _countof(szText), fmt, va);
        if (isConsole())
        {
            fputs(szText, stderr);
        }
        else
        {
            OutputDebugStringA(szText);
        }
    }
    va_end(va);
}

void LogW(LPCWSTR fmt, ...)
{
    WCHAR szText[512];
    va_list va;
    va_start(va, fmt);
    if (s_logFile[0])
    {
        if (FILE *fp = _tfopen(s_logFile, _T("a")))
        {
            vfwprintf(fp, fmt, va);
            fclose(fp);
        }
    }
    else
    {
        StringCchVPrintfW(szText, _countof(szText), fmt, va);
        if (isConsole())
        {
            fputs(W2A(szText, GetConsoleOutputCP()), stderr);
        }
        else
        {
            OutputDebugStringW(szText);
        }
    }
    va_end(va);
}

BOOL isWin64(void)
{
#ifdef _WIN64
    return TRUE;
#else
    return FALSE;
#endif
}

BOOL isWindowsXPOrGreater(void)
{
    OSVERSIONINFO osver = { sizeof(osver) };
    GetVersionEx(&osver);
    if (osver.dwMajorVersion >= 6)
        return TRUE;
    if (osver.dwMajorVersion == 5 && osver.dwMinorVersion >= 1)
        return TRUE;
    return FALSE;
}

BOOL isWindowsVistaOrGreater(void)
{
    OSVERSIONINFO osver = { sizeof(osver) };
    GetVersionEx(&osver);
    return osver.dwMajorVersion >= 6;
}

typedef BOOL (WINAPI *FN_IsWow64Process)(HANDLE, PBOOL);
typedef VOID (WINAPI *FN_GetNativeSystemInfo)(SYSTEM_INFO*);

BOOL isWow64Process(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();

    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    FN_IsWow64Process pIsWow64Process =
        (FN_IsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
    if (!pIsWow64Process)
        return FALSE;

    BOOL bWow64;
    if ((*pIsWow64Process)(hProcess, &bWow64))
        return bWow64;
    return FALSE;
}

LPCSTR W2A(LPCWSTR pszWide, UINT nCodePage)
{
    static CHAR s_aszAnsi[3][1024];
    static INT s_i = 0;
    INT i = s_i;
    s_i = (s_i + 1) % _countof(s_aszAnsi);
    WideCharToMultiByte(nCodePage, 0, pszWide, -1, s_aszAnsi[i], _countof(s_aszAnsi[i]), NULL, NULL);
    s_aszAnsi[i][_countof(s_aszAnsi[i]) - 1] = 0;
    return s_aszAnsi[i];
}

LPCWSTR A2W(LPCSTR pszAnsi, UINT nCodePage)
{
    static WCHAR s_aszWide[3][1024];
    static INT s_i = 0;
    INT i = s_i;
    s_i = (s_i + 1) % _countof(s_aszWide);
    MultiByteToWideChar(nCodePage, 0, pszAnsi, -1, s_aszWide[i], _countof(s_aszWide[i]));
    s_aszWide[i][_countof(s_aszWide[i]) - 1] = 0;
    return s_aszWide[i];
}

LPCSTR A2A(LPCSTR pszAnsi, UINT nCodePage)
{
    return pszAnsi;
}

LPCWSTR W2W(LPCWSTR pszWide, UINT nCodePage)
{
    return pszWide;
}

IMAGE_NT_HEADERS* getNT(LPCTSTR pszExe, BOOL bIsDLL)
{
    TCHAR szFileName[MAX_PATH];
    FILE *fin = _tfopen(pszExe, _T("rb"));
    if (!fin)
    {
        StringCchCopy(szFileName, _countof(szFileName), pszExe);
        if (bIsDLL)
            StringCchCat(szFileName, _countof(szFileName), TEXT(".dll"));
        else
            StringCchCat(szFileName, _countof(szFileName), TEXT(".exe"));
        fin = _tfopen(szFileName, _T("rb"));
    }
    if (!fin)
        return NULL;

    IMAGE_DOS_HEADER dos;
    if (!fread(&dos, sizeof(dos), 1, fin) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        fseek(fin, dos.e_lfanew, SEEK_SET) != 0)
    {
        fclose(fin);
        return NULL;
    }

    IMAGE_NT_HEADERS64 *nt;
    nt = (IMAGE_NT_HEADERS64*)hackAlloc(sizeof(*nt));
    if (!nt)
    {
        fclose(fin);
        return NULL;
    }

    if (!fread(nt, sizeof(*nt), 1, fin) || nt->Signature != IMAGE_NT_SIGNATURE)
    {
        hackFree(nt);
        fclose(fin);
        return NULL;
    }

    fclose(fin);
    return (IMAGE_NT_HEADERS*)nt;
}

WORD getExeMachine(LPCTSTR pszExe, BOOL bIsDLL)
{
    if (!pszExe)
        return getProcessIDMachine(0);

    WORD wMachine = -1;
#if 1
    hackAutoFree<IMAGE_NT_HEADERS> nt = getNT(pszExe, bIsDLL);
    if (nt)
    {
        wMachine = nt->FileHeader.Machine;
    }
#else
    LOADED_IMAGE loaded;
    ZeroMemory(&loaded, sizeof(loaded));
    if (MapAndLoad(T2A(pszExe), NULL, &loaded, bIsDLL, TRUE))
    {
        wMachine = loaded.FileHeader->FileHeader.Machine;
        UnMapAndLoad(&loaded);
    }
#endif
    return wMachine;
}

WORD getProcessMachine(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();

    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileNameEx(hProcess, NULL, szPath, _countof(szPath)))
        return -1;

    return getExeMachine(szPath, FALSE);
}

BOOL isProcessWin32(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();
    if (isWow64Process(hProcess))
        return TRUE;
    return getProcessMachine(hProcess) == IMAGE_FILE_MACHINE_I386;
}

BOOL isProcessWin64(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();
    if (isWow64Process(hProcess))
        return FALSE;
    return getProcessMachine(hProcess) == IMAGE_FILE_MACHINE_AMD64;
}

WORD getProcessIDMachine(DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID));
    return getProcessMachine(hProcess);
}

BOOL isProcessIDWin32(DWORD dwPID)
{
    return getProcessIDMachine(dwPID) == IMAGE_FILE_MACHINE_I386;
}

BOOL isProcessIDWin64(DWORD dwPID)
{
    return getProcessIDMachine(dwPID) == IMAGE_FILE_MACHINE_AMD64;
}

WORD getWindowsArchitecture(VOID)
{
    HINSTANCE hKernel32 = GetModuleHandleA("kernel32");

    SYSTEM_INFO sysinfo;

    FN_GetNativeSystemInfo fnGetNativeSystemInfo;
    fnGetNativeSystemInfo = (FN_GetNativeSystemInfo)GetProcAddress(hKernel32, "GetNativeSystemInfo");
    if (fnGetNativeSystemInfo)
    {
        fnGetNativeSystemInfo(&sysinfo);
        return sysinfo.wProcessorArchitecture;
    }

    GetSystemInfo(&sysinfo);
    return sysinfo.wProcessorArchitecture;
}

BOOL isWindowsWin32(void)
{
    return getWindowsArchitecture() == PROCESSOR_ARCHITECTURE_INTEL;
}

BOOL isWindowsWin64(void)
{
    return getWindowsArchitecture() == PROCESSOR_ARCHITECTURE_AMD64;
}

BOOL getProcessList(std::vector<PROCESSENTRY32>& processes, DWORD dwPID)
{
    processes.clear();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getProcessList: FAILED\n");
        return FALSE;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (dwPID == 0)
            {
                processes.push_back(pe);
            }
            else if (dwPID == pe.th32ProcessID)
            {
                processes.push_back(pe);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    return !processes.empty();
}

BOOL getThreadList(std::vector<THREADENTRY32>& threads, DWORD dwPID, DWORD dwTID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    threads.clear();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getThreadList: FAILED\n");
        return FALSE;
    }

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (dwTID == 0)
            {
                threads.push_back(te);
            }
            else if (dwTID == te.th32ThreadID)
            {
                threads.push_back(te);
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    return !threads.empty();
}

BOOL getModuleList(std::vector<MODULEENTRY32>& modules, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getModuleList: FAILED\n");
        return FALSE;
    }

    MODULEENTRY32 me = { sizeof(me) };

    if (Module32First(hSnapshot, &me))
    {
        do
        {
            modules.push_back(me);
        } while (Module32Next(hSnapshot, &me));
    }

    return TRUE;
}

LPVOID hackReAlloc(LPVOID pvOld, size_t size)
{
    if (!size)
    {
        if (pvOld)
            HeapFree(GetProcessHeap(), 0, pvOld);
        return NULL;
    }
    if (pvOld)
        return HeapReAlloc(GetProcessHeap(), 0, pvOld, size);
    return HeapAlloc(GetProcessHeap(), 0, size);
}

MODULEENTRY32 *getModules(DWORD *pdwCount, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    MODULEENTRY32 *modules = NULL;
    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getModules: FAILED\n");
        return NULL;
    }

    MODULEENTRY32 me = { sizeof(me) };

    DWORD dwIndex = 0;

    if (Module32First(hSnapshot, &me))
    {
        do
        {
            MODULEENTRY32 *old_modules = modules;
            modules = (MODULEENTRY32 *)hackReAlloc(old_modules, (dwIndex + 1) * sizeof(MODULEENTRY32));
            if (modules == NULL)
            {
                free(old_modules);
                dwIndex = 0;
                break;
            }
            modules[dwIndex] = me;
            ++dwIndex;
        } while (Module32Next(hSnapshot, &me));
    }

    *pdwCount = dwIndex;

    return modules;
}

BOOL getModuleByName(MODULEENTRY32& module, LPCTSTR pszName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getModuleByName: FAILED\n");
        return FALSE;
    }

    pszName = PathFindFileName(pszName);

    MODULEENTRY32 me = { sizeof(me) };

    if (Module32First(hSnapshot, &me))
    {
        do
        {
            if (lstrcmpi(me.szModule, pszName) == 0)
            {
                module = me;
                return TRUE;
            }
        } while (Module32Next(hSnapshot, &me));
    }

    LOGA("getModuleByName: FAILED\n");
    return FALSE;
}

BOOL getProcessByName(PROCESSENTRY32& process, LPCTSTR pszName, DWORD dwParentPID)
{
    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        LOGA("getProcessByName: FAILED\n");
        return FALSE;
    }

    pszName = PathFindFileName(pszName);

    PROCESSENTRY32 pe = { sizeof(pe) };

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (dwParentPID && pe.th32ParentProcessID != dwParentPID)
                continue;

            if (lstrcmpi(pe.szExeFile, pszName) == 0)
            {
                process = pe;
                return TRUE;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    LOGA("getProcessByName: FAILED\n");
    return FALSE;
}

BOOL doInjectDll(LPCTSTR pszDllPathName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID));
    if (!hProcess)
    {
        LOGA("doInjectDll: !OpenProcess\n");
        return FALSE;
    }

    if (isWin64())
    {
        if (!isProcessWin64(hProcess))
        {
            LOGA("doInjectDll: !isProcessWin64\n");
            return FALSE;
        }
    }
    else
    {
        if (!isProcessWin32(hProcess))
        {
            LOGA("doInjectDll: !isProcessWin32\n");
            return FALSE;
        }
    }

    DWORD cbParam = (lstrlen(pszDllPathName) + 1) * sizeof(TCHAR);
    LPVOID pParam = VirtualAllocEx(hProcess, NULL, cbParam, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pParam)
    {
        LOGA("doInjectDll: !VirtualAllocEx\n");
        return FALSE;
    }

    WriteProcessMemory(hProcess, pParam, pszDllPathName, cbParam, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32");
#ifdef UNICODE
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
#else
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
#endif
    if (!pLoadLibrary)
    {
        LOGA("doInjectDll: !pLoadLibrary\n");
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pParam, 0, NULL));
    if (!hThread)
    {
        LOGA("doInjectDll: !hThread\n");
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_ABANDONED)
    {
        LOGA("doInjectDll: !WaitForSingleObject\n");
    }

    VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
    return TRUE;
}

BOOL doUninjectDll(LPCTSTR pszDllPathName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID));
    if (!hProcess)
    {
        LOGA("doUninjectDll: !OpenProcess\n");
        return FALSE;
    }

    if (isWin64())
    {
        if (!isProcessWin64(hProcess))
        {
            LOGA("doUninjectDll: !isProcessWin64\n");
            return FALSE;
        }
    }
    else
    {
        if (!isProcessWin32(hProcess))
        {
            LOGA("doUninjectDll: !isProcessWin32\n");
            return FALSE;
        }
    }

    LPCTSTR pszDllName = PathFindFileName(pszDllPathName);

    MODULEENTRY32 me = { sizeof(me) };
    if (!getModuleByName(me, pszDllName, dwPID))
    {
        LOGA("doUninjectDll: !getModuleByName\n");
        return FALSE;
    }

    HMODULE hModule = me.hModule;

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC pLdrUnloadDll = GetProcAddress(hNTDLL, "LdrUnloadDll");
    if (!pLdrUnloadDll)
    {
        LOGA("doUninjectDll: !pLdrUnloadDll\n");
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLdrUnloadDll, hModule, 0, NULL));
    if (!hThread)
    {
        LOGA("doUninjectDll: !hThread\n");
        return FALSE;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_ABANDONED)
    {
        LOGA("doUninjectDll: !WaitForSingleObject\n");
    }

    return TRUE;
}

DWORD getWindowPID(HWND hwnd)
{
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

BOOL enableProcessPriviledge(LPCTSTR pszSE_)
{
    BOOL f;
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    
    f = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValue(NULL, pszSE_, &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            tp.Privileges[0].Luid = luid;
            f = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }
    
    return f;
}

struct WNDANDPID
{
    HWND hwnd;
    DWORD pid;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    DWORD pid = getWindowPID(hwnd);
    WNDANDPID *pInfo = (WNDANDPID *)lParam;
    if (pInfo->pid == pid)
    {
        pInfo->hwnd = hwnd;
        return FALSE;
    }

    EnumChildWindows(hwnd, EnumWindowsProc, lParam);
    if (pInfo->hwnd)
        return FALSE;
    return TRUE;
}

HWND getWindowFromPID(DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    WNDANDPID info = { NULL, dwPID };
    EnumWindows(EnumWindowsProc, (LPARAM)&info);
    return info.hwnd;
}

BOOL getSameFolderPathName(LPTSTR pszPathName, LPCTSTR pszFileTitle, HMODULE hModule)
{
    GetModuleFileName(hModule, pszPathName, MAX_PATH);
    PathRemoveFileSpec(pszPathName);
    PathAppend(pszPathName, pszFileTitle);
    return TRUE;
}

static LPVOID
doImportTable(HMODULE hModule, PIMAGE_IMPORT_DESCRIPTOR pImport, LPCSTR pszFuncName, LPVOID fnNew)
{
    LPBYTE pbBase = (LPBYTE)hModule;
    for (; pImport->OriginalFirstThunk; pImport++)
    {
        LPCSTR pszDllName = (LPCSTR)(pbBase + pImport->Name);
        PIMAGE_THUNK_DATA pThunc, pOriginalThunk;
        pThunc = (PIMAGE_THUNK_DATA)(pbBase + pImport->FirstThunk);
        pOriginalThunk = (PIMAGE_THUNK_DATA)(pbBase + pImport->OriginalFirstThunk);
        for (; pThunc->u1.Function; ++pThunc, ++pOriginalThunk)
        {
            if (HIWORD(pszFuncName) == 0)
            {
                if (!IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
                    continue;

                WORD wOrdinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
                if (wOrdinal != LOWORD(pszFuncName))
                    continue;
            }
            else
            {
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
                    continue;

                PIMAGE_IMPORT_BY_NAME pName =
                    (PIMAGE_IMPORT_BY_NAME)(pbBase + pOriginalThunk->u1.AddressOfData);
                if (_stricmp((LPCSTR)pName->Name, pszFuncName) != 0)
                    continue;
            }

            DWORD dwOldProtect;
            if (!VirtualProtect(&pThunc->u1.Function, sizeof(pThunc->u1.Function),
                                PAGE_READWRITE, &dwOldProtect))
                return NULL;

            LPVOID fnOriginal = (LPVOID)(ULONG_PTR)pThunc->u1.Function;
            WriteProcessMemory(GetCurrentProcess(), &pThunc->u1.Function, &fnNew,
                               sizeof(pThunc->u1.Function), NULL);
            pThunc->u1.Function = (ULONG_PTR)fnNew;

            VirtualProtect(&pThunc->u1.Function, sizeof(pThunc->u1.Function),
                           dwOldProtect, &dwOldProtect);
            return fnOriginal;
        }
    }

    return NULL;
}

LPVOID doHookAPI(HMODULE hModule, LPCSTR pszModuleName, LPCSTR pszFuncName, LPVOID fnNew)
{
    if (!fnNew)
    {
        return NULL;
    }
    if (!pszFuncName)
    {
        return NULL;
    }
    if (!hModule)
        hModule = GetModuleHandleA(NULL);

    DWORD dwSize;
    PIMAGE_IMPORT_DESCRIPTOR pImport;
    pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwSize);
    LPVOID fnOriginal = doImportTable(hModule, pImport, pszFuncName, fnNew);
    return fnOriginal;
}

BOOL startProcess(LPCTSTR cmdline, STARTUPINFO& si, PROCESS_INFORMATION& pi,
                  DWORD dwCreation, LPCTSTR pszCurDir)
{
    assert(cmdline);
    LPTSTR pszCmdLine = _tcsdup(cmdline);
    assert(pszCmdLine);
    BOOL ret = CreateProcess(NULL, pszCmdLine, NULL, NULL, TRUE, dwCreation, NULL, pszCurDir, &si, &pi);
    free(pszCmdLine);
    return ret;
}

static SETTING *s_pSettings = NULL;

BOOL loadSettings(HMODULE hModule, LPCTSTR dllName, SETTING *pSettings)
{
    TCHAR szPath[MAX_PATH] = TEXT("");
    getSameFolderPathName(szPath, dllName, hModule);
    PathRemoveExtension(szPath);
    PathAddExtension(szPath, TEXT(".ini"));

    TCHAR szValue[MAX_PATH];
    for (UINT i = 0; ; ++i)
    {
        SETTING& setting = pSettings[i];
        if (!setting.m_name)
            break;

        GetPrivateProfileString(TEXT("Settings"), pSettings[i].m_name, pSettings[i].m_default,
                                pSettings[i].m_value, _countof(pSettings[i].m_value), szPath);
    }

    s_pSettings = pSettings;
    return TRUE;
}

BOOL saveSettings(HMODULE hModule, LPCTSTR dllName, SETTING *pSettings)
{
    TCHAR szPath[MAX_PATH] = TEXT("");
    getSameFolderPathName(szPath, dllName, hModule);
    PathRemoveExtension(szPath);
    PathAddExtension(szPath, TEXT(".ini"));

    TCHAR szValue[MAX_PATH];
    for (UINT i = 0; ; ++i)
    {
        SETTING& setting = pSettings[i];
        if (!setting.m_name)
            break;

        WritePrivateProfileString(TEXT("Settings"), setting.m_name, setting.m_value, szPath);
    }

    WritePrivateProfileString(NULL, NULL, NULL, szPath);
    s_pSettings = pSettings;
    return TRUE;
}

LPCTSTR getSetting(LPCTSTR keyName)
{
    if (s_pSettings)
    {
        for (UINT i = 0; ; ++i)
        {
            SETTING& setting = s_pSettings[i];
            if (!setting.m_name)
                break;

            if (lstrcmpi(setting.m_name, keyName) == 0)
                return setting.m_value;
        }
    }
    return NULL;
}

BOOL setSetting(LPCTSTR keyName, LPCTSTR fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    BOOL ret = FALSE;
    if (s_pSettings)
    {
        for (UINT i = 0; ; ++i)
        {
            SETTING& setting = s_pSettings[i];
            if (!setting.m_name)
                break;

            if (lstrcmpi(setting.m_name, keyName) == 0)
            {
                StringCchVPrintf(setting.m_value, _countof(setting.m_value), fmt, va);
                ret = TRUE;
                break;
            }
        }
    }
    va_end(va);
    return ret;
}

BOOL doHookTable(HOOK_ENTRY *pEntries, BOOL bHook)
{
    for (UINT iEntry = 0; ; ++iEntry)
    {
        HOOK_ENTRY& entry = pEntries[iEntry];
        if (!entry.dll_name)
            break;

        if (entry.bDisabled)
            continue;

        if (bHook)
        {
            if (entry.fnNew)
                entry.fnOld = doHookAPI(NULL, entry.dll_name, entry.func_name, entry.fnNew);
        }
        else
        {
            if (entry.fnOld)
                entry.fnNew = doHookAPI(NULL, entry.dll_name, entry.func_name, entry.fnOld);
        }
    }
    return TRUE;
}

BOOL doDisableHook(HOOK_ENTRY *pEntries, LPCSTR dll_name, LPCSTR func_name)
{
    BOOL ret = FALSE;

    for (UINT iEntry = 0; ; ++iEntry)
    {
        HOOK_ENTRY& entry = pEntries[iEntry];
        if (!entry.dll_name)
            break;

        if (dll_name && lstrcmpA(entry.dll_name, dll_name) != 0)
            continue;

        if (!func_name || lstrcmpA(entry.func_name, func_name) == 0)
            ret = entry.bDisabled = TRUE;
    }

    return ret;
}
