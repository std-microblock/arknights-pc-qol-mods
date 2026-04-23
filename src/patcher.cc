#include "patcher.h"
#include "blook/blook.h"
#include "blook/disassembly.h"
#include "blook/misc.h"
#include "cpptrace/from_current.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <print>
#include <string>
#include <thread>
#include <vector>


namespace patcher {

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

extern "C" const uint8_t _binary_payload_dll_start[];
extern "C" const uint8_t _binary_payload_dll_end[];

void launch_and_patch() {
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

    auto proc = blook::Process::launch(*name, {
      .suspended = true,
      .detached = true,
    });
    auto tmpdir = std::filesystem::temp_directory_path() / "arkmod.dll";
    std::ofstream ofs(tmpdir, std::ios::binary);
    ofs.write(reinterpret_cast<const char *>(_binary_payload_dll_start),
              _binary_payload_dll_end - _binary_payload_dll_start);
    ofs.close();
    proc->inject(tmpdir.string());
    proc->resume();
  }
  CPPTRACE_CATCH(const std::exception &e) {
    std::println("Error: {}", e.what());
    cpptrace::from_current_exception().print(std::cerr);
  }
}

} // namespace patcher
