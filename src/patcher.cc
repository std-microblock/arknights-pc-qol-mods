#include "patcher.h"
#include "blook/blook.h"
#include "blook/misc.h"
#include "cpptrace/from_current.hpp"
#include <algorithm>
#include <filesystem>
#include <print>
#include <string>
#include <thread>
#include <vector>

namespace patcher {

static void patch_hgsdk(DWORD dwProcessId) {
    CPPTRACE_TRY {
        auto proc = blook::Process::attach(dwProcessId);
        std::println("[hgsdk] waiting for hgsdk.dll...");
        while (!proc->module("hgsdk.dll").has_value()) {
            Sleep(10);
        }
        auto sdk = proc->module("hgsdk.dll").value();
        sdk->base().add(0xc9f30).write_u8('1');
        std::println("[hgsdk] Bypassed hgsdk platform");
    }
    CPPTRACE_CATCH(const std::exception &e) {
        std::println("[hgsdk] Error: {}", e.what());
    }
}

static void patch_framerate(DWORD dwProcessId) {
    CPPTRACE_TRY {
        auto proc = blook::Process::attach(dwProcessId);
        std::println("[framerate] waiting for GameAssembly.dll...");
        while (!proc->module("gameassembly.dll").has_value()) {
            Sleep(10);
        }
        auto gameAssembly = proc->module("gameassembly.dll").value();

        std::println("[framerate] Start patching framerate limit...");
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
                std::println("[framerate] Found at {}", instr.ptr().data());
                instr.ptr()
                    .reassembly([](zasm::x86::Assembler asb) {
                        asb.mov(zasm::x86::rcx, Imm32(144));
                        asb.jmp(zasm::x86::rax);
                    })
                    .patch();
                break;
            }
        }
        std::println("[framerate] Framerate limit patched");
    }
    CPPTRACE_CATCH(const std::exception &e) {
        std::println("[framerate] Error: {}", e.what());
    }
}

ProcessInfo launch_and_patch() {
    ProcessInfo result{nullptr, 0};
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

        result.hProcess = pi.hProcess;
        result.dwProcessId = pi.dwProcessId;
        CloseHandle(pi.hThread);

        std::println("Process created: pid {}", pi.dwProcessId);

        std::thread(patch_hgsdk, pi.dwProcessId).detach();
        std::thread(patch_framerate, pi.dwProcessId).detach();
    }
    CPPTRACE_CATCH(const std::exception &e) {
        std::println("Error: {}", e.what());
        cpptrace::from_current_exception().print(std::cerr);
    }
    return result;
}

} // namespace patcher
