#pragma once
#include <Windows.h>

namespace patcher {

struct ProcessInfo {
    HANDLE hProcess;
    DWORD dwProcessId;
};

ProcessInfo launch_and_patch();

} // namespace patcher
