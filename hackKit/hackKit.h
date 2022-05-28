#pragma once

#ifndef _INC_WINDOWS
    #include <windows.h>
#endif
#include <tlhelp32.h>
#include <vector>

BOOL isConsole(void);

struct AutoCloseHandle
{
    HANDLE m_h;
    AutoCloseHandle(HANDLE h) : m_h(h)
    {
    }
    ~AutoCloseHandle()
    {
        CloseHandle(m_h);
    }
    operator HANDLE&()
    {
        return m_h;
    }
};

void LogA(LPCSTR fmt, ...);
void LogW(LPCWSTR fmt, ...);
#ifdef UNICODE
    #define Log LogW
#else
    #define Log LogA
#endif

#define LOGA LogA
#define LOGW LogW
#define LOG Log

void setLogFile(LPCTSTR filename = NULL);

BOOL isWin64(void);
BOOL isWindowsXPOrGreater(void);
BOOL isWindowsVistaOrGreater(void);
BOOL isWindowsWin32(void);
BOOL isWindowsWin64(void);
BOOL IsWow64Process(HANDLE hProcess = NULL);
BOOL isProcessWin32(HANDLE hProcess = NULL);
BOOL isProcessWin64(HANDLE hProcess = NULL);
BOOL isProcessIDWin32(DWORD dwPID = 0);
BOOL isProcessIDWin64(DWORD dwPID = 0);

LPCSTR A2A(LPCSTR pszAnsi, UINT nCodePage = CP_ACP);
LPCWSTR W2W(LPCWSTR pszWide, UINT nCodePage = CP_ACP);
LPCSTR W2A(LPCWSTR pszWide, UINT nCodePage = CP_ACP);
LPCWSTR A2W(LPCSTR pszAnsi, UINT nCodePage = CP_ACP);

#ifdef UNICODE
    #define A2T A2W
    #define W2T W2W
    #define T2A W2A
    #define T2W W2W
    #define T2T W2W
#else
    #define A2T A2A
    #define W2T W2A
    #define T2A A2A
    #define T2W A2W
    #define T2T A2A
#endif

WORD getWindowsArchitecture(VOID);
WORD getExeMachine(LPCTSTR pszExe = NULL, BOOL bIsDLL = FALSE);
WORD getProcessMachine(HANDLE hProcess = NULL);
WORD getProcessIDMachine(DWORD dwPID = 0);

BOOL getProcessList(std::vector<PROCESSENTRY32>& processes, DWORD dwPID = 0);
BOOL getThreadList(std::vector<THREADENTRY32>& threads, DWORD dwPID = 0, DWORD dwTID = 0);
BOOL getModuleList(std::vector<MODULEENTRY32>& modules, DWORD dwPID = 0);

LPVOID hackReAlloc(LPVOID pvOld, size_t size);
#define hackAlloc(size) hackReAlloc(NULL, (size))
#define hackFree(pvOld) hackReAlloc((pvOld), 0)

template <typename T_BASE = void>
struct hackAutoFree
{
    T_BASE *m_p;
    hackAutoFree(T_BASE *p) : m_p(p)
    {
    }
    ~hackAutoFree()
    {
        hackFree(m_p);
    }
    operator T_BASE*&()
    {
        return m_p;
    }
    T_BASE& operator*()
    {
        return *m_p;
    }
    T_BASE* operator->()
    {
        return m_p;
    }
};

IMAGE_NT_HEADERS* getNT(LPCTSTR pszExe, BOOL bIsDLL); // needs hackFree

MODULEENTRY32 *getModules(DWORD *pdwCount, DWORD dwPID); // needs hackFree

BOOL getProcessByName(PROCESSENTRY32& process, LPCTSTR pszName, DWORD dwParentPID = 0);
BOOL getModuleByName(MODULEENTRY32& module, LPCTSTR pszName, DWORD dwPID = 0);

DWORD getWindowPID(HWND hwnd);
HWND getWindowFromPID(DWORD dwPID = 0);

BOOL enableProcessPriviledge(LPCTSTR pszSE_);

BOOL doInjectDll(LPCTSTR pszDllPathName, DWORD dwPID = 0);
BOOL doUninjectDll(LPCTSTR pszDllPathName, DWORD dwPID = 0);
BOOL getSameFolderPathName(LPTSTR pszPathName, LPCTSTR pszFileTitle, HMODULE hModule = NULL);

LPVOID doHookAPI(HMODULE hTargetModule, LPCSTR pszModuleName, LPCSTR pszFuncName, LPVOID fnNew);
BOOL startProcess(LPCTSTR cmdline, STARTUPINFO& si, PROCESS_INFORMATION& pi,
                  DWORD dwCreation = 0, LPCTSTR pszCurDir = NULL);

struct SETTING
{
    LPCTSTR m_name;
    LPCTSTR m_default;
    TCHAR m_value[MAX_PATH];
};

BOOL loadSettings(HMODULE hModule, LPCTSTR dllName, SETTING *pSettings);
BOOL saveSettings(HMODULE hModule, LPCTSTR dllName, SETTING *pSettings);
LPCTSTR getSetting(LPCTSTR keyName);
BOOL setSetting(LPCTSTR keyName, LPCTSTR fmt, ...);

#define STRINGIFY(x) #x

struct HOOK_ENTRY
{
    LPCSTR dll_name;
    LPCSTR func_name;
    LPVOID fnNew;
    LPVOID fnOld;
    BOOL bDisabled;
};

BOOL doHookTable(HOOK_ENTRY *pEntries, BOOL bHook = TRUE);
BOOL doDisableHook(HOOK_ENTRY *pEntries, LPCSTR dll_name, LPCSTR func_name = NULL);
