#include <windows.h>
#include "../../hackKit/hackKit.h"
#include <shlwapi.h>
#include <mmsystem.h>
#include <tchar.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#define PAYLOAD_NAME TEXT("SpeedUp")
#define DEFAULT_SPEED 1.5

typedef DWORDLONG (WINAPI *FN_GetTickCount64)(VOID);
FN_GetTickCount64 g_fnGetTickCount64 = NULL;

static DWORD s_dwTickEpic;
static DWORDLONG s_dwlTick64Epic;
static DWORD s_dwMMTimeEpic;
static ULARGE_INTEGER s_uliLocalEpic;
static ULARGE_INTEGER s_uliSystemEpic;
BOOL s_bPerfCounter;
static LARGE_INTEGER s_PerfCounterFreq;
static LARGE_INTEGER s_PerfCounterEpic;
static time_t s_timeEpic;
static clock_t s_clockEpic;

static double s_eSpeed = DEFAULT_SPEED;
static BOOL s_bGetTickCount = TRUE;
static BOOL s_bGetTickCount64 = TRUE;
static BOOL s_btimeGetTime = TRUE;
static BOOL s_bGetLocalTime = TRUE;
static BOOL s_bGetSystemTime = TRUE;
static BOOL s_bSetTimer = TRUE;
static BOOL s_bQueryPerformanceCounter = TRUE;
static BOOL s_btime = TRUE;
static BOOL s_bclock = TRUE;
static BOOL s_bSleep = TRUE;

void recordEpic(void)
{
    SYSTEMTIME stLocal, stSystem;
    FILETIME ftLocal, ftSystem;

    s_dwTickEpic = GetTickCount();
    if (g_fnGetTickCount64)
        s_dwlTick64Epic = (*g_fnGetTickCount64)();
    s_dwMMTimeEpic = timeGetTime();
    GetLocalTime(&stLocal);
    GetSystemTime(&stSystem);

    SystemTimeToFileTime(&stLocal, &ftLocal);
    s_uliLocalEpic.LowPart = ftLocal.dwLowDateTime;
    s_uliLocalEpic.HighPart = ftLocal.dwHighDateTime;

    SystemTimeToFileTime(&stSystem, &ftSystem);
    s_uliSystemEpic.LowPart = ftSystem.dwLowDateTime;
    s_uliSystemEpic.HighPart = ftSystem.dwHighDateTime;

    s_bPerfCounter = QueryPerformanceFrequency(&s_PerfCounterFreq);
    QueryPerformanceCounter(&s_PerfCounterEpic);

    s_timeEpic = time(NULL);
    s_clockEpic = clock();
}

EXTERN_C __declspec(dllexport)
DWORD WINAPI DetourGetTickCount(VOID)
{
    DWORD dwTick = GetTickCount();
    return DWORD((dwTick - s_dwTickEpic) * s_eSpeed) + s_dwTickEpic;
}

EXTERN_C __declspec(dllexport)
DWORDLONG WINAPI DetourGetTickCount64(VOID)
{
    if (!g_fnGetTickCount64)
        return DetourGetTickCount();
    DWORDLONG dwlTick64 = (*g_fnGetTickCount64)();
    return DWORD((dwlTick64 - s_dwlTick64Epic) * s_eSpeed) + s_dwlTick64Epic;
}

EXTERN_C __declspec(dllexport)
DWORD WINAPI DetourtimeGetTime(VOID)
{
    DWORD dwMMTime = timeGetTime();
    return DWORD((dwMMTime - s_dwMMTimeEpic) * s_eSpeed) + s_dwMMTimeEpic;
}

EXTERN_C __declspec(dllexport)
VOID WINAPI DetourGetSystemTime(LPSYSTEMTIME pst)
{
    if (!pst)
        return;

    SYSTEMTIME st;
    GetSystemTime(&st);

    FILETIME ft;
    ULARGE_INTEGER uli;
    SystemTimeToFileTime(&st, &ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    uli.QuadPart -= s_uliSystemEpic.QuadPart;
    uli.QuadPart = DWORDLONG(uli.QuadPart * s_eSpeed);
    uli.QuadPart += s_uliSystemEpic.QuadPart;

    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    FileTimeToSystemTime(&ft, &st);

    *pst = st;
}

EXTERN_C __declspec(dllexport)
VOID WINAPI DetourGetLocalTime(LPSYSTEMTIME pst)
{
    if (!pst)
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    FILETIME ft;
    ULARGE_INTEGER uli;
    SystemTimeToFileTime(&st, &ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    uli.QuadPart -= s_uliLocalEpic.QuadPart;
    uli.QuadPart = DWORDLONG(uli.QuadPart * s_eSpeed);
    uli.QuadPart += s_uliLocalEpic.QuadPart;

    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    FileTimeToSystemTime(&ft, &st);

    *pst = st;
}

EXTERN_C __declspec(dllexport)
UINT WINAPI DetourSetTimer(HWND hWnd, UINT id, UINT elapse, TIMERPROC fn)
{
    if (s_eSpeed > 0)
        elapse = UINT(elapse / (1.0f * s_eSpeed));
    return SetTimer(hWnd, id, elapse, fn);
}

EXTERN_C __declspec(dllexport)
BOOL WINAPI DetourQueryPerformanceCounter(LARGE_INTEGER *pli)
{
    if (!s_bPerfCounter || !pli)
        return FALSE;

    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    li.QuadPart -= s_PerfCounterEpic.QuadPart;
    li.QuadPart = DWORDLONG(li.QuadPart * s_eSpeed);
    li.QuadPart += s_PerfCounterEpic.QuadPart;
    *pli = li;
    return TRUE;
}

EXTERN_C __declspec(dllexport)
time_t __cdecl Detourtime(time_t *pt)
{
    time_t t = time(NULL);
    t -= s_timeEpic;
    t = time_t(t * s_eSpeed);
    t += s_timeEpic;
    if (pt)
        *pt = t;
    return t;
}

EXTERN_C __declspec(dllexport)
clock_t __cdecl Detourclock(void)
{
    clock_t c = clock();
    c -= s_clockEpic;
    c = clock_t(c * s_eSpeed);
    c += s_clockEpic;
    return c;
}

EXTERN_C __declspec(dllexport)
VOID WINAPI DetourSleep(DWORD dwMilliseconds)
{
    if (s_eSpeed > 0)
    {
        dwMilliseconds = DWORD(dwMilliseconds / s_eSpeed);
    }
    Sleep(dwMilliseconds);
}

__declspec(dllexport) SETTING g_settings[] =
{
    { TEXT("Speed"), TEXT(STRINGIFY(DEFAULT_SPEED)) },
    { TEXT("GetTickCount"), TEXT("1") },
    { TEXT("GetTickCount64"), TEXT("1") },
    { TEXT("timeGetTime"), TEXT("1") },
    { TEXT("GetLocalTime"), TEXT("1") },
    { TEXT("GetSystemTime"), TEXT("1") },
    { TEXT("SetTimer"), TEXT("1") },
    { TEXT("QueryPerformanceCounter"), TEXT("1") },
    { TEXT("time"), TEXT("1") },
    { TEXT("clock"), TEXT("1") },
    { TEXT("Sleep"), TEXT("1") },
    { NULL },
};

__declspec(dllexport) HOOK_ENTRY g_hooks[] =
{
#define DO_ENTRY(dll_name, func_name) { dll_name, #func_name, (LPVOID)Detour##func_name },
DO_ENTRY("kernel32.dll", GetTickCount)
DO_ENTRY("kernel32.dll", GetTickCount64)
DO_ENTRY("winmm.dll", timeGetTime)
DO_ENTRY("kernel32.dll", GetLocalTime)
DO_ENTRY("kernel32.dll", GetSystemTime)
DO_ENTRY("kernel32.dll", SetTimer)
DO_ENTRY("kernel32.dll", QueryPerformanceCounter)
DO_ENTRY("msvcrt.dll", time)
DO_ENTRY("msvcrtd.dll", time)
DO_ENTRY("msvcr80.dll", time)
DO_ENTRY("msvcr80d.dll", time)
DO_ENTRY("msvcr90.dll", time)
DO_ENTRY("msvcr90d.dll", time)
DO_ENTRY("msvcr100.dll", time)
DO_ENTRY("msvcr100d.dll", time)
DO_ENTRY("msvcr110.dll", time)
DO_ENTRY("msvcr110d.dll", time)
DO_ENTRY("msvcr120.dll", time)
DO_ENTRY("msvcr120d.dll", time)
DO_ENTRY("msvcrt.dll", clock)
DO_ENTRY("msvcrtd.dll", clock)
DO_ENTRY("msvcr80.dll", clock)
DO_ENTRY("msvcr80d.dll", clock)
DO_ENTRY("msvcr90.dll", clock)
DO_ENTRY("msvcr90d.dll", clock)
DO_ENTRY("msvcr100.dll", clock)
DO_ENTRY("msvcr100d.dll", clock)
DO_ENTRY("msvcr110.dll", clock)
DO_ENTRY("msvcr110d.dll", clock)
DO_ENTRY("msvcr120.dll", clock)
DO_ENTRY("msvcr120d.dll", clock)
DO_ENTRY("kernel32.dll", Sleep)
    { NULL },
};

BOOL init(HMODULE hPayload)
{
    g_fnGetTickCount64 = (FN_GetTickCount64)GetProcAddress(GetModuleHandleA("kernel32"), "GetTickCount64");

    recordEpic();

    // load settings
    loadSettings(hPayload, PAYLOAD_NAME, g_settings);
    s_eSpeed = _tcstod(getSetting(TEXT("Speed")), NULL);
    s_bGetTickCount = (BOOL)_tcstol(getSetting(TEXT("GetTickCount")), NULL, 0);
    s_bGetTickCount64 = (BOOL)_tcstol(getSetting(TEXT("GetTickCount64")), NULL, 0);
    s_btimeGetTime = (BOOL)_tcstol(getSetting(TEXT("timeGetTime")), NULL, 0);
    s_bGetLocalTime = (BOOL)_tcstol(getSetting(TEXT("GetLocalTime")), NULL, 0);
    s_bGetSystemTime = (BOOL)_tcstol(getSetting(TEXT("GetSystemTime")), NULL, 0);
    s_bSetTimer = (BOOL)_tcstol(getSetting(TEXT("SetTimer")), NULL, 0);
    s_bQueryPerformanceCounter = (BOOL)_tcstol(getSetting(TEXT("QueryPerformanceCounter")), NULL, 0);
    s_btime = (BOOL)_tcstol(getSetting(TEXT("time")), NULL, 0);
    s_bclock = (BOOL)_tcstol(getSetting(TEXT("clock")), NULL, 0);
    s_bSleep = (BOOL)_tcstol(getSetting(TEXT("Sleep")), NULL, 0);

    // adjust settings
    if (s_eSpeed <= 0)
        s_eSpeed = DEFAULT_SPEED;

    // update settings
    setSetting(TEXT("Speed"), TEXT("%f"), s_eSpeed);
    setSetting(TEXT("GetTickCount"), TEXT("%d"), s_bGetTickCount);
    setSetting(TEXT("GetTickCount64"), TEXT("%d"), s_bGetTickCount64);
    setSetting(TEXT("timeGetTime"), TEXT("%d"), s_btimeGetTime);
    setSetting(TEXT("GetLocalTime"), TEXT("%d"), s_bGetLocalTime);
    setSetting(TEXT("GetSystemTime"), TEXT("%d"), s_bGetSystemTime);
    setSetting(TEXT("SetTimer"), TEXT("%d"), s_bSetTimer);
    setSetting(TEXT("QueryPerformanceCounter"), TEXT("%d"), s_bQueryPerformanceCounter);
    setSetting(TEXT("time"), TEXT("%d"), s_btime);
    setSetting(TEXT("clock"), TEXT("%d"), s_bclock);
    setSetting(TEXT("Sleep"), TEXT("%d"), s_bSleep);
    saveSettings(hPayload, PAYLOAD_NAME, g_settings);

    // disable hooks if necessary
    if (!s_bGetTickCount)
        doDisableHook(g_hooks, "kernel32.dll", "GetTickCount");
    if (!s_bGetTickCount64)
        doDisableHook(g_hooks, "kernel32.dll", "GetTickCount64");
    if (!s_btimeGetTime)
        doDisableHook(g_hooks, "winmm.dll", "timeGetTime");
    if (!s_bGetLocalTime)
        doDisableHook(g_hooks, "kernel32.dll", "GetLocalTime");
    if (!s_bGetSystemTime)
        doDisableHook(g_hooks, "kernel32.dll", "GetSystemTime");
    if (!s_bSetTimer)
        doDisableHook(g_hooks, "kernel32.dll", "SetTimer");
    if (!s_bQueryPerformanceCounter)
        doDisableHook(g_hooks, "kernel32.dll", "QueryPerformanceCounter");
    if (!s_btime)
        doDisableHook(g_hooks, NULL, "time");
    if (!s_bclock)
        doDisableHook(g_hooks, NULL, "clock");
    if (!s_bSleep)
        doDisableHook(g_hooks, "kernel32.dll", "Sleep");

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
        doHookTable(g_hooks, TRUE);
        break;

    case DLL_PROCESS_DETACH:
        doHookTable(g_hooks, FALSE);
        break;
    }
    return TRUE;
}
