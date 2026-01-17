#include "macro.h"
#include "patcher.h"
#include <Windows.h>
#include <iostream>
#include <thread>

int main() {
    patcher::ProcessInfo info = patcher::launch_and_patch();
    if (!info.hProcess) {
        std::cerr << "Failed to launch or patch!" << std::endl;
        return 1;
    }

    std::thread macro_thread([]() {
        macro::start_mouse_hook();
    });

    WaitForSingleObject(info.hProcess, INFINITE);
    
    macro::stop_mouse_hook();
    if (macro_thread.joinable()) {
        macro_thread.join();
    }
    CloseHandle(info.hProcess);

    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    return main();
}
