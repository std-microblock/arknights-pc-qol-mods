#include "blook/blook.h"
#include "blook/misc.h"
#include <filesystem>
#include <print>

#include <Windows.h>
#include <algorithm>

#include "cpptrace/from_current.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

#include <iostream>
#include <string>
#include <windows.h>

#include <iostream>
#include <string>
#include <windows.h>

const std::wstring TARGET_TITLE = L"明日方舟";

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
  INPUT inputs[2] = {};

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

bool ignoreNextRightClick = false;
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

int main() {
  HHOOK hMouseHook =
      SetWindowsHookEx(WH_MOUSE_LL, MouseProc, GetModuleHandle(NULL), 0);

  if (!hMouseHook) {
    std::cerr << "钩子安装失败！" << std::endl;
    return 1;
  }

  std::cout << "程序运行中，监听窗口: 明日方舟..." << std::endl;
  std::cout << "按 Ctrl+C 退出。" << std::endl;

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  UnhookWindowsHookEx(hMouseHook);
  return 0;
}

int main_launch() {
  CPPTRACE_TRY {

    auto path = std::filesystem::path(__argv[0]);
    std::filesystem::current_path(path.parent_path());

    auto names = std::vector<std::string>{
        "C:\\arknights\\Arknights Game\\Arknights.exe", "Arknights.exe"};
    auto name = std::ranges::find_if(
        names, [](const auto &name) { return std::filesystem::exists(name); });

    if (name == names.end()) {
      throw std::runtime_error("Arknights.exe not found");
    }

    PROCESS_INFORMATION pi{};
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    if (!CreateProcessA(name->c_str(), nullptr, 0, 0, FALSE,
                        CREATE_NO_WINDOW | DETACHED_PROCESS |
                            CREATE_BREAKAWAY_FROM_JOB,
                        nullptr, nullptr, &si, &pi)) {
      throw std::runtime_error("Failed to create process");
    }

    auto proc = blook::Process::attach(pi.dwProcessId);
    std::println("pid: {}", pi.dwProcessId);
    while (!proc->module("hgsdk.dll").has_value()) {
      Sleep(10);
    }
    proc->process_module().value()->inject(
        "D:\\arknights-research\\pc\\frida-gadget-17.2.11-windows-x86_64.dll");
    std::println("Game modules loaded");
    auto sdk = proc->module("hgsdk.dll").value();
    sdk->base().add(0xc9f30).write_u8('1');
    std::println("Bypassed hgsdk platform");

    auto gameAssembly = proc->modules()["gameassembly.dll"];
    if (!gameAssembly) {
      throw std::runtime_error("GameAssembly.dll not found");
    }

    std::println("Start patching framerate limit...");
    auto set_framerate_text = gameAssembly->section(".rdata")->find_one_remote(
        "UnityEngine.Application::set_targetFrameRate(System.Int32)");
    if (!set_framerate_text.has_value())
      throw std::runtime_error("set_targetFrameRate not found");
    auto fn_setTargetFrameRate =
        gameAssembly->section("il2cpp")->find_xref(set_framerate_text.value());
    if (!fn_setTargetFrameRate.has_value())
      throw std::runtime_error("setTargetFrameRate function not found");
    auto disasm = fn_setTargetFrameRate.value().range_size(100).disassembly();
    for (const auto &instr : disasm) {
      using namespace zasm;
      if (instr->getMnemonic() == x86::Mnemonic::Jmp) {
        std::println("Found at {}", instr.ptr().data());
        instr.ptr()
            .reassembly([](zasm::x86::Assembler asb) {
              asb.mov(zasm::x86::rcx, Imm32(144));
              asb.jmp(zasm::x86::rax);
            })
            .patch();
        break;
      }
    }
  }
  CPPTRACE_CATCH(const std::exception &e) {
    std::print("Error: {}\n", e.what());
    cpptrace::from_current_exception().print(std::cerr);
  }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  main();
  return 0;
}