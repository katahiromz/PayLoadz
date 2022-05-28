#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <mmsystem.h>
#include <strsafe.h>

BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
    DWORD dwProcessID = GetCurrentProcessId();
    SetDlgItemInt(hwnd, edt1, (UINT)dwProcessID, FALSE);
    SetTimer(hwnd, 999, 500, NULL);
    return TRUE;
}

void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    switch (id)
    {
    case IDOK:
    case IDCANCEL:
        KillTimer(hwnd, 999);
        EndDialog(hwnd, id);
        break;
    case psh1:
        MessageBox(hwnd, TEXT("Being Unhooked!"), TEXT("Being Unhooked!"), MB_ICONINFORMATION);
        break;
    }
}

void OnTimer(HWND hwnd, UINT id)
{
    if (id != 999)
        return;

    DWORD dwTick = GetTickCount();
    DWORD dwMultiMediaTime = timeGetTime();

    SYSTEMTIME stLocal, stSystem;
    GetLocalTime(&stLocal);
    GetSystemTime(&stSystem);

    TCHAR szText[MAX_PATH];

    StringCchPrintf(szText, _countof(szText), TEXT("%08lX"), dwTick);
    SetDlgItemText(hwnd, edt2, szText);

    StringCchPrintf(szText, _countof(szText), TEXT("%04u-%02u-%02u %02u:%02u:%02u"),
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    SetDlgItemText(hwnd, edt3, szText);

    StringCchPrintf(szText, _countof(szText), TEXT("%04u-%02u-%02u %02u:%02u:%02u"),
        stSystem.wYear, stSystem.wMonth, stSystem.wDay, stSystem.wHour, stSystem.wMinute, stSystem.wSecond);
    SetDlgItemText(hwnd, edt4, szText);

    StringCchPrintf(szText, _countof(szText), TEXT("%08lX"), dwMultiMediaTime);
    SetDlgItemText(hwnd, edt5, szText);
}

INT_PTR CALLBACK
DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        HANDLE_MSG(hwnd, WM_INITDIALOG, OnInitDialog);
        HANDLE_MSG(hwnd, WM_COMMAND, OnCommand);
        HANDLE_MSG(hwnd, WM_TIMER, OnTimer);
    }
    return 0;
}

INT APIENTRY WinMain(
    HINSTANCE   hInstance,
    HINSTANCE   hPrevInstance,
    LPSTR       lpCmdLine,
    INT         nCmdShow)
{
    InitCommonControls();
    DialogBoxW(hInstance, MAKEINTRESOURCEW(1), NULL, DialogProc);
    return 0;
}
