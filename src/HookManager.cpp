#include "HookManager.h"
#include "WardenScanner.h"
#include "Logger.h"
#include <MinHook.h>
#include <array>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <sstream>

namespace HookManager {

    struct HookInfo {
        const char* name;
        LPVOID target;
    };

    constexpr size_t kHookCount = 2;

    std::array<HookInfo, kHookCount> g_Hooks = {};
    size_t g_HookCount = 0;
    std::mutex g_HookMutex;
    bool g_Initialized = false;
    thread_local bool g_InsideHook = false;

    using fnVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using fnVirtualProtectEx = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

    fnVirtualProtect g_OriginalVirtualProtect = nullptr;
    fnVirtualProtectEx g_OriginalVirtualProtectEx = nullptr;

    class HookCallGuard {
    public:
        HookCallGuard() {
            g_InsideHook = true;
        }

        ~HookCallGuard() {
            g_InsideHook = false;
        }
    };

    std::wstring StatusMessage(MH_STATUS status) {
        const char* statusText = MH_StatusToString(status);
        return std::wstring(statusText, statusText + std::strlen(statusText));
    }

    std::wstring ToWide(const char* text) {
        return std::wstring(text, text + std::strlen(text));
    }

    void LogMinHookError(const wchar_t* operation, const char* hookName, MH_STATUS status) {
        Logger::Log(L"[Hook] " + std::wstring(operation) + L" failed for " +
                    ToWide(hookName) +
                    L": " + StatusMessage(status));
    }

    template<typename T>
    bool CreateApiHook(const char* name, LPVOID detour, T* original) {
        LPVOID target = nullptr;
        MH_STATUS status = MH_CreateHookApiEx(
            L"kernel32.dll",
            name,
            detour,
            reinterpret_cast<LPVOID*>(original),
            &target);
        if (status != MH_OK) {
            LogMinHookError(L"MH_CreateHookApiEx", name, status);
            return false;
        }

        g_Hooks[g_HookCount++] = {name, target};
        return true;
    }

    void ResetOriginalFunctions() {
        g_OriginalVirtualProtect = nullptr;
        g_OriginalVirtualProtectEx = nullptr;
    }

    void RemoveCreatedHooks() {
        for (size_t i = 0; i < g_HookCount; ++i) {
            MH_RemoveHook(g_Hooks[i].target);
        }
        g_HookCount = 0;
        ResetOriginalFunctions();
    }

    std::wstring ToHex(uintptr_t value) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << value;
        return ss.str();
    }

    bool ShouldScanProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return (baseProtect == PAGE_EXECUTE ||
                baseProtect == PAGE_EXECUTE_READ ||
                baseProtect == PAGE_EXECUTE_READWRITE ||
                baseProtect == PAGE_EXECUTE_WRITECOPY);
    }

    BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        if (g_InsideHook) {
            return g_OriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }

        HookCallGuard guard;
        BOOL result = g_OriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

        if (result) {
            Logger::Log(L"[Hook] VirtualProtect called. Base: " + ToHex((uintptr_t)lpAddress) +
                        L", Size: " + ToHex(dwSize) +
                        L", NewProtect: " + ToHex(flNewProtect));

            if (ShouldScanProtection(flNewProtect)) {
                WardenScanner::QueueScan(lpAddress);
            }
        }
        return result;
    }

    BOOL WINAPI HookedVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        if (g_InsideHook) {
            return g_OriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }

        HookCallGuard guard;
        BOOL result = g_OriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

        if (result && (hProcess == GetCurrentProcess() || GetProcessId(hProcess) == GetCurrentProcessId())) {
            Logger::Log(L"[Hook] VirtualProtectEx called. Base: " + ToHex((uintptr_t)lpAddress) +
                        L", Size: " + ToHex(dwSize) +
                        L", NewProtect: " + ToHex(flNewProtect));

            if (ShouldScanProtection(flNewProtect)) {
                WardenScanner::QueueScan(lpAddress);
            }
        }
        return result;
    }

    bool InitializeHooks() {
        std::lock_guard<std::mutex> lock(g_HookMutex);

        if (g_Initialized) {
            return true;
        }

        MH_STATUS status = MH_Initialize();
        if (status != MH_OK) {
            Logger::Log(L"[Hook] MH_Initialize failed: " + StatusMessage(status));
            return false;
        }

        bool success =
            CreateApiHook("VirtualProtect", reinterpret_cast<LPVOID>(HookedVirtualProtect), &g_OriginalVirtualProtect) &&
            CreateApiHook("VirtualProtectEx", reinterpret_cast<LPVOID>(HookedVirtualProtectEx), &g_OriginalVirtualProtectEx);

        if (success) {
            for (size_t i = 0; i < g_HookCount; ++i) {
                status = MH_QueueEnableHook(g_Hooks[i].target);
                if (status != MH_OK) {
                    LogMinHookError(L"MH_QueueEnableHook", g_Hooks[i].name, status);
                    success = false;
                    break;
                }
            }
        }

        if (success) {
            status = MH_ApplyQueued();
            if (status != MH_OK) {
                Logger::Log(L"[Hook] MH_ApplyQueued failed: " + StatusMessage(status));
                success = false;
            }
        }

        if (!success) {
            MH_DisableHook(MH_ALL_HOOKS);
            RemoveCreatedHooks();
            MH_Uninitialize();
            return false;
        }

        g_Initialized = true;
        for (size_t i = 0; i < g_HookCount; ++i) {
            Logger::Log(L"[Hook] Successfully hooked " + ToWide(g_Hooks[i].name));
        }
        return true;
    }

    void RemoveHooks() {
        std::lock_guard<std::mutex> lock(g_HookMutex);
        if (!g_Initialized) {
            return;
        }

        MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
        if (status != MH_OK) {
            Logger::Log(L"[Hook] MH_DisableHook failed: " + StatusMessage(status));
        }

        for (size_t i = 0; i < g_HookCount; ++i) {
            Logger::Log(L"[Hook] Removed hook from " + ToWide(g_Hooks[i].name));
        }

        RemoveCreatedHooks();
        status = MH_Uninitialize();
        if (status != MH_OK) {
            Logger::Log(L"[Hook] MH_Uninitialize failed: " + StatusMessage(status));
        }
        g_Initialized = false;
    }
}
