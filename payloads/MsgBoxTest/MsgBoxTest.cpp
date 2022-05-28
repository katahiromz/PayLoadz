#include <windows.h>
#include <commctrl.h>
#include "../../hackKit/hackKit.h"
#include <shlwapi.h>
#include <mmsystem.h>
#include <tchar.h>
#include <stdlib.h>
#include <assert.h>

#define PAYLOAD_NAME TEXT("MsgBoxTest")
#define DEFAULT_MESSAGE TEXT("Being Hooked")
#define DEFAULT_TITLE TEXT("Being Hooked")

LPCSTR getMessageA(LPCSTR text)
{
    LPCSTR pszText = T2A(getSetting(TEXT("Message")));
    if (lstrcmpA(pszText, "(default)") == 0)
        return text;
    if (lstrcmpA(pszText, "(null)") == 0)
        return NULL;
    return pszText;
}

LPCWSTR getMessageW(LPCWSTR text)
{
    LPCWSTR pszText = T2W(getSetting(TEXT("Message")));
    if (lstrcmpW(pszText, L"(default)") == 0)
        return text;
    if (lstrcmpW(pszText, L"(null)") == 0)
        return NULL;
    return pszText;
}

LPCSTR getTitleA(LPCSTR title)
{
    LPCSTR pszTitle = T2A(getSetting(TEXT("Title")));
    if (lstrcmpA(pszTitle, "(default)") == 0)
        return title;
    if (lstrcmpA(pszTitle, "(null)") == 0)
        return NULL;
    return pszTitle;
}

LPCWSTR getTitleW(LPCWSTR title)
{
    LPCWSTR pszTitle = T2W(getSetting(TEXT("Title")));
    if (lstrcmpW(pszTitle, L"(default)") == 0)
        return title;
    if (lstrcmpW(pszTitle, L"(null)") == 0)
        return NULL;
    return pszTitle;
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxA(HWND hwnd, LPCSTR text, LPCSTR title, UINT uType)
{
    return MessageBoxA(hwnd, getMessageA(text), getTitleA(title), uType);
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxW(HWND hwnd, LPCWSTR text, LPCWSTR title, UINT uType)
{
    return MessageBoxW(hwnd, getMessageW(text), getTitleW(title), uType);
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxExA(HWND hwnd, LPCSTR text, LPCSTR title, UINT uType, WORD wLangId)
{
    return MessageBoxExA(hwnd, getMessageA(text), getTitleA(title), uType, wLangId);
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxExW(HWND hwnd, LPCWSTR text, LPCWSTR title, UINT uType, WORD wLangId)
{
    return MessageBoxExW(hwnd, getMessageW(text), getTitleW(title), uType, wLangId);
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxIndirectA(LPMSGBOXPARAMSA pParams)
{
    if (!pParams)
        return 0;
    MSGBOXPARAMSA params = *pParams;
    params.lpszText = getMessageA(params.lpszText);
    params.lpszCaption = getTitleA(params.lpszCaption);
    return MessageBoxIndirectA(&params);
}

EXTERN_C __declspec(dllexport)
INT WINAPI DetourMessageBoxIndirectW(LPMSGBOXPARAMSW pParams)
{
    if (!pParams)
        return 0;
    MSGBOXPARAMSW params = *pParams;
    params.lpszText = getMessageW(params.lpszText);
    params.lpszCaption = getTitleW(params.lpszCaption);
    return MessageBoxIndirectW(&params);
}

__declspec(dllexport) SETTING g_settings[] =
{
    { TEXT("Message"), DEFAULT_MESSAGE },
    { TEXT("Title"), DEFAULT_TITLE },
    { NULL },
};

__declspec(dllexport) HOOK_ENTRY g_hooks[] =
{
#define DO_ENTRY(dll_name, func_name) { dll_name, #func_name, (LPVOID)Detour##func_name },
DO_ENTRY("kernel32.dll", MessageBoxA)
DO_ENTRY("kernel32.dll", MessageBoxW)
DO_ENTRY("kernel32.dll", MessageBoxExA)
DO_ENTRY("kernel32.dll", MessageBoxExW)
DO_ENTRY("kernel32.dll", MessageBoxIndirectA)
DO_ENTRY("kernel32.dll", MessageBoxIndirectW)
    { NULL },
};

BOOL init(HMODULE hPayload)
{
    loadSettings(hPayload, PAYLOAD_NAME, g_settings);
    saveSettings(hPayload, PAYLOAD_NAME, g_settings);
    return TRUE;
}

EXTERN_C BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!init(hinstDLL))
            return FALSE;
        doHookTable(g_hooks);
        break;

    case DLL_PROCESS_DETACH:
        doHookTable(g_hooks, FALSE);
        break;
    }
    return TRUE;
}
