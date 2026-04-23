#include "macro.h"
#include "patcher.h"
#include <Windows.h>
#include <iostream>
#include <thread>

int main() {
  try {
    patcher::launch_and_patch();
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;

    wchar_t errorMessage[512];
    const auto s = std::string("Error: ") + e.what();
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, errorMessage, 512);
    MessageBoxW(NULL, errorMessage, L"Error", MB_ICONERROR | MB_OK);
    return 1;
  }

  // std::thread macro_thread([]() {
  //     macro::start_mouse_hook();
  // });

  // WaitForSingleObject(info.hProcess, INFINITE);

  // macro::stop_mouse_hook();
  // if (macro_thread.joinable()) {
  //     macro_thread.join();
  // }
  // CloseHandle(info.hProcess);

  return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  return main();
}
