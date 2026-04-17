#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <thread>

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_RELOAD 1002

class UIManager {
public:
    UIManager() : hwnd(NULL) {}

    void Start() {
        std::thread([this]() { CreateTrayWindow(); }).detach();
    }

private:
    HWND hwnd;
    NOTIFYICONDATA nid = { sizeof(nid) };

    void CreateTrayWindow() {
        WNDCLASS wc = {0};
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"BypassTSPU_UI";
        RegisterClass(&wc);

        hwnd = CreateWindow(L"BypassTSPU_UI", L"BypassTSPU", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, this);

        memset(&nid, 0, sizeof(nid));
        nid.cbSize = sizeof(nid);
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // Use standard app icon
        lstrcpy(nid.szTip, L"Bypass TSPU - Active");
        lstrcpy(nid.szInfoTitle, L"Bypass Status");
        lstrcpy(nid.szInfo, L"DPI Bypass is now active!");

        Shell_NotifyIcon(NIM_ADD, &nid);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (msg == WM_TRAYICON) {
            if (lParam == WM_RBUTTONUP) {
                POINT curPoint;
                GetCursorPos(&curPoint);
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, ID_TRAY_RELOAD, L"Reload Config");
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
                
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, curPoint.x, curPoint.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
        } else if (msg == WM_COMMAND) {
            if (LOWORD(wParam) == ID_TRAY_EXIT) {
                PostQuitMessage(0);
                exit(0);
            } else if (LOWORD(wParam) == ID_TRAY_RELOAD) {
                std::cout << "[*] Reloading configuration..." << std::endl;
                // Logic to reload config would trigger here
            }
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
};
