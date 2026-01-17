#include "macro.h"
#include <Windows.h>
#include <iostream>
#include <string>
#include <thread>

namespace macro {

const std::wstring TARGET_TITLE = L"明日方舟";
bool ignoreNextRightClick = false;
HHOOK hMouseHook = nullptr;

void SendEscKey() {
    INPUT inputs[2] = {};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_ESCAPE;
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = VK_ESCAPE;
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, inputs, sizeof(INPUT));
}

void SendRightDown() {
    INPUT inputs[1] = {};
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
    SendInput(1, inputs, sizeof(INPUT));
}

void SleepMicroseconds(long long microseconds) {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    long long elapsed = 0;
    do {
        QueryPerformanceCounter(&end);
        elapsed = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;
    } while (elapsed < microseconds);
}

void PerformPauseDrag() {
    POINT pt;
    GetCursorPos(&pt);
    SendEscKey();
    ignoreNextRightClick = true;
    SendRightDown();
    SleepMicroseconds(2000);
    SetCursorPos(pt.x, pt.y - 10);
    SleepMicroseconds(5000);
    SendEscKey();
    SetCursorPos(pt.x, pt.y);
}

LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_RBUTTONDOWN) {
        if (ignoreNextRightClick) {
            ignoreNextRightClick = false;
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }
        HWND hwnd = GetForegroundWindow();
        wchar_t windowTitle[256];
        GetWindowTextW(hwnd, windowTitle, 256);

        if (std::wstring(windowTitle).find(TARGET_TITLE) != std::wstring::npos) {
            std::thread(PerformPauseDrag).detach();
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void start_mouse_hook() {
    hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseProc, GetModuleHandle(NULL), 0);
    if (!hMouseHook) {
        std::cerr << "Failed to install mouse hook!" << std::endl;
        return;
    }

    std::cout << "Macro launched." << std::endl;
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void stop_mouse_hook() {
    if (hMouseHook) {
        UnhookWindowsHookEx(hMouseHook);
        hMouseHook = nullptr;
        PostQuitMessage(0);
    }
}

} // namespace macro
