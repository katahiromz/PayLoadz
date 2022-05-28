#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <tchar.h>
#include <psapi.h>
#include <shlwapi.h>
#include <assert.h>
#include <string>
#include <map>
#include <algorithm>
#include "../hackKit/hackKit.h"
#include <strsafe.h>

#ifdef UNICODE
    typedef std::wstring tstring_t;
#else
    typedef std::string tstring_t;
#endif

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

HINSTANCE g_hInst = NULL;
HWND g_hMainWnd = NULL;

void errorBox(HWND hwnd, RET ret)
{
    INT id = 0;
    switch (ret)
    {
    case RET_OK:
        return;
    case RET_INVALID_ARG: id = 201; break;
    case RET_INVALID_PAYLOAD: id = 202; break;
    case RET_BITS_MISMATCH_PROCESS: id = 203; break;
    case RET_BITS_MISMATCH_PAYLOAD: id = 204; break;
    case RET_BITS_MISMATCH_EXE: id = 205; break;
    case RET_CANNOT_RUN: id = 206; break;
    case RET_CANNOT_INJECT: id = 207; break;
    case RET_CANNOT_UNINJECT: id = 208; break;
    case RET_LOGICAL_ERROR: id = 209; break;
    case RET_INVALID_EXE: id = 210; break;
    }

    TCHAR szText[MAX_PATH];
    LoadString(g_hInst, id, szText, _countof(szText));
    MessageBox(hwnd, szText, TEXT("PayLordz"), MB_ICONERROR);
}

struct ENTRY
{
    tstring_t name;
    tstring_t title;
    tstring_t pathname32;
    tstring_t pathname64;
    BOOL checked = FALSE;
};
typedef std::map<tstring_t, ENTRY> entry_map_t;
entry_map_t g_entries;

BOOL getCheckedPayloads(std::vector<ENTRY>& payloads)
{
    payloads.clear();
    for (auto& pair : g_entries)
    {
        if (pair.second.checked)
        {
            payloads.push_back(pair.second);
        }
    }
    return !payloads.empty();
}

BOOL canChecked(HWND hwnd, BOOL bChecked)
{
    HWND hLst1 = GetDlgItem(hwnd, lst1);

    if ((INT)SendMessage(hLst1, LB_GETSELCOUNT, 0, 0) == 0)
        return FALSE;

    BOOL ret = FALSE;
    INT i, nCount = (INT)SendMessage(hLst1, LB_GETCOUNT, 0, 0);
    for (i = 0; i < nCount; ++i)
    {
        BOOL bSelected = ((INT)SendMessage(hLst1, LB_GETSEL, i, 0) > 0);
        if (!bSelected)
            continue;

        TCHAR szText[MAX_PATH];
        szText[0] = 0;
        SendMessage(hLst1, LB_GETTEXT, i, (LPARAM)szText);
        if (LPTSTR pch = _tcsstr(szText, TEXT(": ")))
            *pch = 0;

        if (g_entries[szText].checked != bChecked)
        {
            ret = TRUE;
            break;
        }
    }

    return ret;
}

// See: https://devblogs.microsoft.com/oldnewthing/20040804-00/?p=38243
BOOL safeEnableWindow(HWND hwnd, BOOL bEnable)
{
    if (GetWindowLongPtr(hwnd, GWL_STYLE) & WS_CHILD)
    {
        HWND hParent = GetParent(hwnd);
        if (hwnd == GetFocus() && !bEnable)
        {
            SendMessage(hParent, WM_NEXTDLGCTL, 0, FALSE);
        }
    }
    return EnableWindow(hwnd, bEnable);
}

void OnSelOrCheckChange(HWND hwnd)
{
    HWND hPsh1 = GetDlgItem(hwnd, psh1);
    HWND hPsh2 = GetDlgItem(hwnd, psh2);
    HWND hLst1 = GetDlgItem(hwnd, lst1);

    safeEnableWindow(hPsh1, canChecked(hwnd, TRUE));
    safeEnableWindow(hPsh2, canChecked(hwnd, FALSE));

    BOOL bAnyChecked = FALSE;
    INT i, nCount = (INT)SendMessage(hLst1, LB_GETCOUNT, 0, 0);
    for (i = 0; i < nCount; ++i)
    {
        TCHAR szText[MAX_PATH];
        szText[0] = 0;
        SendMessage(hLst1, LB_GETTEXT, i, (LPARAM)szText);
        if (LPTSTR pch = _tcsstr(szText, TEXT(": ")))
            *pch = 0;

        if (g_entries[szText].checked)
        {
            bAnyChecked = TRUE;
            break;
        }
    }

    safeEnableWindow(GetDlgItem(hwnd, psh5), bAnyChecked);
    safeEnableWindow(GetDlgItem(hwnd, psh6), bAnyChecked);
    safeEnableWindow(GetDlgItem(hwnd, psh8), bAnyChecked);
}

void doCheck(HWND hwnd, INT iItem, BOOL bToggle, BOOL bCheck = FALSE)
{
    HWND hLst1 = GetDlgItem(hwnd, lst1);

    TCHAR szText[MAX_PATH];
    szText[0] = 0;
    SendMessage(hLst1, LB_GETTEXT, iItem, (LPARAM)szText);
    if (LPTSTR pch = _tcsstr(szText, TEXT(": ")))
        *pch = 0;

    if (bToggle)
        g_entries[szText].checked = !g_entries[szText].checked;
    else
        g_entries[szText].checked = bCheck;

    InvalidateRect(hLst1, NULL, TRUE);
    OnSelOrCheckChange(hwnd);
}

tstring_t getPayloadPathName(LPCTSTR filename)
{
    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("payloads"));
    BOOL bPayloadFolder = PathIsDirectory(szPath);

    tstring_t ret = filename;

    tstring_t dll;
    if (bPayloadFolder)
    {
        dll = TEXT("payloads\\");
        dll += filename;
        getSameFolderPathName(szPath, dll.c_str());
    }
    else
    {
        getSameFolderPathName(szPath, filename);
    }

    return szPath;
}

tstring_t getPayloadValue(LPCTSTR filename, INT id)
{
    tstring_t pathname = getPayloadPathName(filename);

    HINSTANCE hDLL = LoadLibraryEx(pathname.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hDLL)
        return TEXT("");

    tstring_t ret;
    TCHAR szText[MAX_PATH];
    szText[0] = 0;
    if (LoadString(hDLL, id, szText, _countof(szText)))
    {
        ret = szText;
    }

    FreeLibrary(hDLL);
    return ret;
}

BOOL isValidPayload(LPCTSTR filename)
{
    return getPayloadValue(filename, 100) == TEXT("PayLordz");
}

void doSetFile(HWND hwnd, LPCTSTR pszFile)
{
    tstring_t str = TEXT("\"");
    str += pszFile;
    str += TEXT('"');
    SetDlgItemText(hwnd, edt2, str.c_str());
}

BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
    g_hMainWnd = hwnd;
    DragAcceptFiles(hwnd, TRUE);

    // TODO: Enable buttons
    safeEnableWindow(GetDlgItem(hwnd, psh3), FALSE);
    safeEnableWindow(GetDlgItem(hwnd, psh4), FALSE);

    // Get payloads
    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("payloads"));
    if (PathIsDirectory(szPath))
    {
        getSameFolderPathName(szPath, TEXT("payloads\\*.dll"));
    }
    else
    {
        getSameFolderPathName(szPath, TEXT("*.dll"));
    }

    // populate the entries
    g_entries.clear();
    WIN32_FIND_DATA find;
    HANDLE hFind = FindFirstFile(szPath, &find);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (isValidPayload(find.cFileName))
            {
                tstring_t name = getPayloadValue(find.cFileName, 102);
                tstring_t pathname = getPayloadPathName(find.cFileName);
                tstring_t title = getPayloadValue(find.cFileName, 101);

                if (g_entries.find(name) == g_entries.end())
                {
                    ENTRY entry = { name, title };
                    g_entries.insert(std::make_pair(name, entry));
                }

                WORD wMachine = getExeMachine(pathname.c_str(), TRUE);
                switch (wMachine)
                {
                case IMAGE_FILE_MACHINE_I386:
                    g_entries[name].pathname32 = pathname;
                    break;
                case IMAGE_FILE_MACHINE_AMD64:
                    g_entries[name].pathname64 = pathname;
                    break;
                }
            }
        } while (FindNextFile(hFind, &find));
        FindClose(hFind);
    }

    // Add the entries to listbox
    for (auto& pair : g_entries)
    {
        tstring_t text = pair.first;
        text += TEXT(": ");
        auto& entry = pair.second;
        if (entry.pathname32.size() && entry.pathname64.size())
        {
            text += TEXT("(32/64) ");
        }
        else if (entry.pathname32.size())
        {
            text += TEXT("(32) ");
        }
        else if (entry.pathname64.size())
        {
            text += TEXT("(64) ");
        }
        text += entry.title;
        SendDlgItemMessage(hwnd, lst1, LB_ADDSTRING, 0, (LPARAM)text.c_str());
    }

#ifdef _WIN64
    getSameFolderPathName(szPath, TEXT("target64.exe"));
#else
    getSameFolderPathName(szPath, TEXT("target32.exe"));
#endif
    doSetFile(hwnd, szPath);

    OnSelOrCheckChange(hwnd);
    return TRUE;
}

void OnEdt1(HWND hwnd)
{
#ifdef _WIN64
    SetDlgItemText(hwnd, stc1, NULL);
#else
    SetDlgItemText(hwnd, stc1, TEXT("32-bit process only"));
#endif

    TCHAR szText[64];
    szText[0] = 0;
    Edit_GetText(GetDlgItem(hwnd, edt1), szText, _countof(szText));
    StrTrim(szText, TEXT(" \t"));

    TCHAR *endptr;
    DWORD pid = _tcstoul(szText, &endptr, 0);
    if (endptr && *endptr)
        return;

    AutoCloseHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!hProcess)
        return;

    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileNameEx(hProcess, NULL, szPath, _countof(szPath)))
        return;

    SetDlgItemText(hwnd, stc1, PathFindFileName(szPath));
}

void OnCheck(HWND hwnd, BOOL bToggle, BOOL bCheck = TRUE)
{
    HWND hLst1 = GetDlgItem(hwnd, lst1);

    INT i, nCount = (INT)SendMessage(hLst1, LB_GETCOUNT, 0, 0);

    if (bToggle && !(INT)SendMessage(hLst1, LB_GETSELCOUNT, 0, 0))
    {
        i = (INT)SendMessage(hLst1, LB_GETCARETINDEX, 0, 0);
        SendMessage(hLst1, LB_SETSEL, TRUE, i);
        InvalidateRect(hLst1, NULL, TRUE);
        return;
    }

    for (i = 0; i < nCount; ++i)
    {
        BOOL bSelected = ((INT)SendMessage(hLst1, LB_GETSEL, i, 0) > 0);
        if (!bSelected)
            continue;

        if (bToggle)
            doCheck(hwnd, i, TRUE);
        else
            doCheck(hwnd, i, FALSE, bCheck);
    }

    InvalidateRect(hLst1, NULL, TRUE);
}

void OnToggleCheck(HWND hwnd)
{
    HWND hLst1 = GetDlgItem(hwnd, lst1);

    INT i = (INT)SendMessage(hLst1, LB_GETCARETINDEX, i, 0);

    BOOL bSelected = ((INT)SendMessage(hLst1, LB_GETSEL, i, 0) > 0);
    if (!bSelected)
        return;

    doCheck(hwnd, i, TRUE);
    InvalidateRect(hLst1, NULL, TRUE);
}

void OnBrowse(HWND hwnd)
{
    TCHAR szFile[MAX_PATH] = TEXT("");
    OPENFILENAME ofn = { sizeof(ofn), hwnd };
    ofn.lpstrFilter = TEXT("Executable (*.exe)\0*.exe\0");
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = _countof(szFile);
    ofn.lpstrTitle = TEXT("Choose a program file");
    ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING | OFN_FILEMUSTEXIST |
                OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;
    ofn.lpstrDefExt = TEXT("EXE");
    if (GetOpenFileName(&ofn))
    {
        doSetFile(hwnd, szFile);
    }
}

tstring_t getArg0(LPCTSTR pszCmdLine)
{
    tstring_t ret;
    if (*pszCmdLine == TEXT('"'))
    {
        ++pszCmdLine;
        LPCTSTR pch = _tcschr(pszCmdLine, TEXT('"'));
        if (pch == NULL)
            return pszCmdLine;
        ret.assign(pszCmdLine, pch - pszCmdLine);
    }
    else
    {
        size_t ich = _tcscspn(pszCmdLine, TEXT(" \t"));
        if (ich == _tcslen(pszCmdLine))
            return pszCmdLine;
        ret.assign(pszCmdLine, ich);
    }
    return ret;
}

BOOL doRun32(HWND hwnd, LPCTSTR arg0, LPCTSTR pszCmdLine)
{
    std::vector<ENTRY> payloads;
    getCheckedPayloads(payloads);

    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("injector32.exe"));
    tstring_t cmdline = TEXT("\"");
    cmdline += szPath;
    cmdline += TEXT("\"");

    for (auto& entry : payloads)
    {
        if (entry.pathname32.size())
        {
            cmdline += TEXT(" --payload \"");
            cmdline += entry.pathname32;
            cmdline += TEXT("\"");
        }
    }

    cmdline += TEXT(" --run ");
    cmdline += pszCmdLine;

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    StringCchCopy(szPath, _countof(szPath), arg0);
    PathRemoveFileSpec(szPath);

    PROCESS_INFORMATION pi = { NULL };
    BOOL ret = startProcess(cmdline.c_str(), si, pi, CREATE_NEW_CONSOLE, szPath);

    if (ret)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if ((RET)dwExitCode != RET_OK)
        {
            ret = FALSE;
            errorBox(hwnd, (RET)dwExitCode);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        PROCESSENTRY32 pe = { sizeof(pe) };
        getProcessByName(pe, arg0, pi.dwProcessId);
        SetDlgItemInt(hwnd, edt1, pe.th32ProcessID, FALSE);
    }
    else
    {
        SetDlgItemText(hwnd, edt1, NULL);
    }

    return ret;
}

BOOL doRun64(HWND hwnd, LPCTSTR arg0, LPCTSTR pszCmdLine)
{
    std::vector<ENTRY> payloads;
    getCheckedPayloads(payloads);

    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("injector64.exe"));
    tstring_t cmdline = TEXT("\"");
    cmdline += szPath;
    cmdline += TEXT("\"");

    for (auto& entry : payloads)
    {
        if (entry.pathname64.size())
        {
            cmdline += TEXT(" --payload \"");
            cmdline += entry.pathname64;
            cmdline += TEXT("\"");
        }
    }

    cmdline += TEXT(" --run ");
    cmdline += pszCmdLine;

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    StringCchCopy(szPath, _countof(szPath), arg0);
    PathRemoveFileSpec(szPath);

    PROCESS_INFORMATION pi = { NULL };
    BOOL ret = startProcess(cmdline.c_str(), si, pi, CREATE_NEW_CONSOLE, szPath);

    if (ret)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if ((RET)dwExitCode != RET_OK)
        {
            ret = FALSE;
            errorBox(hwnd, (RET)dwExitCode);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        PROCESSENTRY32 pe = { sizeof(pe) };
        getProcessByName(pe, arg0, pi.dwProcessId);
        SetDlgItemInt(hwnd, edt1, pe.th32ProcessID, FALSE);
    }
    else
    {
        SetDlgItemText(hwnd, edt1, NULL);
    }

    return ret;
}

void OnRunInjected(HWND hwnd)
{
    TCHAR szCmdLine[1024];
    GetDlgItemText(hwnd, edt2, szCmdLine, _countof(szCmdLine));
    StrTrim(szCmdLine, TEXT(" \t\r\n"));

    tstring_t arg0 = getArg0(szCmdLine);
    WORD wMachine = getExeMachine(arg0.c_str());

    switch (wMachine)
    {
    case IMAGE_FILE_MACHINE_I386:
        doRun32(hwnd, arg0.c_str(), szCmdLine);
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        doRun64(hwnd, arg0.c_str(), szCmdLine);
        break;
    }
}

BOOL doInject32(HWND hwnd, DWORD pid, BOOL bInject)
{
    std::vector<ENTRY> payloads;
    getCheckedPayloads(payloads);

    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("injector32.exe"));
    tstring_t cmdline = TEXT("\"");
    cmdline += szPath;
    cmdline += TEXT("\"");

    for (auto& entry : payloads)
    {
        if (entry.pathname32.size())
        {
            cmdline += TEXT(" --payload \"");
            cmdline += entry.pathname32;
            cmdline += TEXT("\"");
        }
    }

    if (bInject)
        cmdline += TEXT(" --inject ");
    else
        cmdline += TEXT(" --uninject ");

#ifdef UNICODE
    cmdline += std::to_wstring(pid);
#else
    cmdline += std::to_string(pid);
#endif

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { NULL };
    BOOL ret = startProcess(cmdline.c_str(), si, pi, CREATE_NEW_CONSOLE);

    if (ret)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if ((RET)dwExitCode != RET_OK)
        {
            ret = FALSE;
            errorBox(hwnd, (RET)dwExitCode);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        // TODO: Error message
    }

    return ret;
}

BOOL doInject64(HWND hwnd, DWORD pid, BOOL bInject)
{
    std::vector<ENTRY> payloads;
    getCheckedPayloads(payloads);

    TCHAR szPath[MAX_PATH];
    getSameFolderPathName(szPath, TEXT("injector64.exe"));
    tstring_t cmdline = TEXT("\"");
    cmdline += szPath;
    cmdline += TEXT("\"");

    for (auto& entry : payloads)
    {
        if (entry.pathname64.size())
        {
            cmdline += TEXT(" --payload \"");
            cmdline += entry.pathname64;
            cmdline += TEXT("\"");
        }
    }

    if (bInject)
        cmdline += TEXT(" --inject ");
    else
        cmdline += TEXT(" --uninject ");

#ifdef UNICODE
    cmdline += std::to_wstring(pid);
#else
    cmdline += std::to_string(pid);
#endif

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { NULL };
    BOOL ret = startProcess(cmdline.c_str(), si, pi, CREATE_NEW_CONSOLE);

    if (ret)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if ((RET)dwExitCode != RET_OK)
        {
            ret = FALSE;
            errorBox(hwnd, (RET)dwExitCode);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        // TODO: Error message
    }

    return ret;
}

void OnInjectPayloads(HWND hwnd)
{
    DWORD pid = GetDlgItemInt(hwnd, edt1, NULL, FALSE);
    if (isProcessIDWin64(pid))
        doInject64(hwnd, pid, TRUE);
    else if (isProcessIDWin32(pid))
        doInject32(hwnd, pid, TRUE);
}

void OnUninjectPayloads(HWND hwnd)
{
    DWORD pid = GetDlgItemInt(hwnd, edt1, NULL, FALSE);
    if (isProcessIDWin64(pid))
        doInject64(hwnd, pid, FALSE);
    else if (isProcessIDWin32(pid))
        doInject32(hwnd, pid, FALSE);
}

void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    switch (id)
    {
    case IDOK:
    case IDCANCEL:
        EndDialog(hwnd, id);
        break;
    case edt1:
        if (codeNotify == EN_CHANGE)
        {
            OnEdt1(hwnd);
        }
        break;
    case psh1:
        OnCheck(hwnd, FALSE, TRUE);
        break;
    case psh2:
        OnCheck(hwnd, FALSE, FALSE);
        break;
    case lst1:
        switch (codeNotify)
        {
        case LBN_DBLCLK:
            OnToggleCheck(hwnd);
            break;
        case LBN_SELCHANGE:
            OnSelOrCheckChange(hwnd);
            break;
        }
        break;
    case psh5:
        OnInjectPayloads(hwnd);
        break;
    case psh6:
        OnUninjectPayloads(hwnd);
        break;
    case psh7:
        OnBrowse(hwnd);
        break;
    case psh8:
        OnRunInjected(hwnd);
        break;
    }
}

void OnDestroy(HWND hwnd)
{
    g_hMainWnd = NULL;
}

void OnMeasureItem(HWND hwnd, MEASUREITEMSTRUCT * lpMeasureItem)
{
    if (lpMeasureItem->CtlID != lst1)
        return;

    lpMeasureItem->itemHeight = 20;
}

void OnDrawItem(HWND hwnd, const DRAWITEMSTRUCT * lpDrawItem)
{
    if (lpDrawItem->CtlID != lst1)
        return;

    TCHAR szText[MAX_PATH];
    szText[0] = 0;
    SendDlgItemMessage(hwnd, lst1, LB_GETTEXT, lpDrawItem->itemID, (LPARAM)szText);
    tstring_t strText = szText;
    if (LPTSTR pch = _tcsstr(szText, TEXT(": ")))
        *pch = 0;

    HDC hDC = lpDrawItem->hDC;

    RECT rcItem = lpDrawItem->rcItem;

    if (lpDrawItem->itemState & ODS_SELECTED)
        FillRect(hDC, &rcItem, (HBRUSH)(COLOR_HIGHLIGHT + 1));
    else
        FillRect(hDC, &rcItem, (HBRUSH)(COLOR_WINDOW + 1));

    InflateRect(&rcItem, -2, -2);

    RECT rcCheck = rcItem;
    rcCheck.right = rcCheck.left + 16;
    InflateRect(&rcCheck, -1, -1);

    UINT uState = DFCS_BUTTONCHECK | DFCS_MONO;
    if (g_entries[szText].checked)
        uState |= DFCS_CHECKED;
    DrawFrameControl(hDC, &rcCheck, DFC_BUTTON, uState);

    rcItem.left += 20;
    UINT uFormat = DT_SINGLELINE | DT_LEFT | DT_VCENTER | DT_NOPREFIX;
    if (lpDrawItem->itemState & ODS_SELECTED)
        SetTextColor(hDC, GetSysColor(COLOR_HIGHLIGHTTEXT));
    else
        SetTextColor(hDC, GetSysColor(COLOR_WINDOWTEXT));
    SetBkMode(hDC, TRANSPARENT);
    DrawText(hDC, strText.c_str(), -1, &rcItem, uFormat);
}

LRESULT OnNotify(HWND hwnd, int idFrom, LPNMHDR pnmhdr)
{
    return 0;
}

int OnVkeyToItem(HWND hwnd, UINT vk, HWND hwndListbox, int iCaret)
{
    if (vk == VK_SPACE)
    {
        OnCheck(hwnd, TRUE);
    }
    else if (vk == L'A' && GetKeyState(VK_CONTROL) < 0)
    {
        HWND hLst1 = GetDlgItem(hwnd, lst1);
        INT nCount = ListBox_GetCount(hLst1);
        ListBox_SelItemRange(hLst1, TRUE, 0, nCount);
    }
    return SetDlgMsgResult(hwnd, WM_VKEYTOITEM, -1);
}

INT_PTR CALLBACK
DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        HANDLE_MSG(hwnd, WM_INITDIALOG, OnInitDialog);
        HANDLE_MSG(hwnd, WM_COMMAND, OnCommand);
        HANDLE_MSG(hwnd, WM_DESTROY, OnDestroy);
        HANDLE_MSG(hwnd, WM_MEASUREITEM, OnMeasureItem);
        HANDLE_MSG(hwnd, WM_DRAWITEM, OnDrawItem);
        HANDLE_MSG(hwnd, WM_NOTIFY, OnNotify);
        HANDLE_MSG(hwnd, WM_VKEYTOITEM, OnVkeyToItem);
    }
    return 0;
}

INT WINAPI
WinMain(HINSTANCE   hInstance,
        HINSTANCE   hPrevInstance,
        LPSTR       lpCmdLine,
        INT         nCmdShow)
{
    g_hInst = hInstance;
    InitCommonControls();
    enableProcessPriviledge(SE_DEBUG_NAME);

    if (lstrcmpiA(lpCmdLine, "--monitor") == 0)
    {
        DialogBox(hInstance, MAKEINTRESOURCE(2), NULL, DialogProc);
    }
    else
    {
        DialogBox(hInstance, MAKEINTRESOURCE(1), NULL, DialogProc);
    }
    return 0;
}
