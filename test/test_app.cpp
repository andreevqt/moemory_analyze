#include <windows.h>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

using WardenDetectorShutdownFn = BOOL(WINAPI*)();
using WardenDetectorWaitForReadyFn = BOOL(WINAPI*)(DWORD);

namespace {
    constexpr SIZE_T kWardenImageSize = 3 * 0x1000;

    std::wstring GetDumpPattern(PVOID address) {
        std::wstringstream pattern;
        pattern << L"warden_" << std::hex << reinterpret_cast<uintptr_t>(address) << L"_*.bin";
        return pattern.str();
    }

    void DeleteExistingDumps(PVOID address) {
        WIN32_FIND_DATAW findData = {};
        HANDLE findHandle = FindFirstFileW(GetDumpPattern(address).c_str(), &findData);
        if (findHandle == INVALID_HANDLE_VALUE) {
            return;
        }

        do {
            DeleteFileW(findData.cFileName);
        } while (FindNextFileW(findHandle, &findData));
        FindClose(findHandle);
    }

    PVOID CreateSimulatedWarden(BYTE sectionMarker) {
        PVOID allocation = VirtualAlloc(
            nullptr,
            kWardenImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (allocation == nullptr) {
            return nullptr;
        }

        DeleteExistingDumps(allocation);
        memcpy(allocation, "BLL2", 4);
        memset(static_cast<BYTE*>(allocation) + 0x1000, sectionMarker, 0x1000);

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                static_cast<BYTE*>(allocation) + 0x1000,
                0x1000,
                PAGE_EXECUTE_READ,
                &oldProtect)) {
            VirtualFree(allocation, 0, MEM_RELEASE);
            return nullptr;
        }

        return allocation;
    }

    PVOID CreateExecutableDecoy() {
        PVOID allocation = VirtualAlloc(
            nullptr,
            kWardenImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (allocation == nullptr) {
            return nullptr;
        }

        DeleteExistingDumps(allocation);
        memcpy(allocation, "MZ\0\0", 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                static_cast<BYTE*>(allocation) + 0x1000,
                0x1000,
                PAGE_EXECUTE_READ,
                &oldProtect)) {
            VirtualFree(allocation, 0, MEM_RELEASE);
            return nullptr;
        }

        return allocation;
    }

    bool HasDump(PVOID address) {
        WIN32_FIND_DATAW findData = {};
        HANDLE findHandle = FindFirstFileW(GetDumpPattern(address).c_str(), &findData);
        if (findHandle == INVALID_HANDLE_VALUE) {
            return false;
        }

        FindClose(findHandle);
        return true;
    }

    bool HasValidDump(PVOID address, BYTE expectedMarker) {
        WIN32_FIND_DATAW findData = {};
        HANDLE findHandle = FindFirstFileW(GetDumpPattern(address).c_str(), &findData);
        if (findHandle == INVALID_HANDLE_VALUE) {
            return false;
        }

        std::wstring dumpPath = findData.cFileName;
        FindClose(findHandle);

        HANDLE dumpFile = CreateFileW(
            dumpPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (dumpFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        LARGE_INTEGER fileSize = {};
        BYTE signature[4] = {};
        BYTE sectionMarker = 0;
        DWORD bytesRead = 0;
        bool valid = GetFileSizeEx(dumpFile, &fileSize) &&
                     fileSize.QuadPart == static_cast<LONGLONG>(kWardenImageSize) &&
                     ReadFile(dumpFile, signature, sizeof(signature), &bytesRead, nullptr) &&
                     bytesRead == sizeof(signature) &&
                     memcmp(signature, "BLL2", sizeof(signature)) == 0;

        LARGE_INTEGER markerOffset = {};
        markerOffset.QuadPart = 0x1000;
        valid = valid &&
                SetFilePointerEx(dumpFile, markerOffset, nullptr, FILE_BEGIN) &&
                ReadFile(dumpFile, &sectionMarker, sizeof(sectionMarker), &bytesRead, nullptr) &&
                bytesRead == sizeof(sectionMarker) && sectionMarker == expectedMarker;

        CloseHandle(dumpFile);
        return valid;
    }

    struct DetectorApi {
        HMODULE module = nullptr;
        WardenDetectorShutdownFn shutdown = nullptr;
        WardenDetectorWaitForReadyFn waitForReady = nullptr;
    };

    bool LoadDetector(DetectorApi& detector) {
        detector.module = LoadLibraryW(L"WardenDetector.dll");
        if (detector.module == nullptr) {
            return false;
        }

        detector.shutdown = reinterpret_cast<WardenDetectorShutdownFn>(
            GetProcAddress(detector.module, "WardenDetectorShutdown"));
        detector.waitForReady = reinterpret_cast<WardenDetectorWaitForReadyFn>(
            GetProcAddress(detector.module, "WardenDetectorWaitForReady"));
        return detector.shutdown != nullptr && detector.waitForReady != nullptr;
    }

    bool ShutdownDetector(DetectorApi& detector) {
        if (detector.module == nullptr || detector.shutdown == nullptr) {
            return false;
        }

        bool success = detector.shutdown() != FALSE;
        success = success && FreeLibrary(detector.module) != FALSE;
        detector = {};
        return success;
    }

    bool TestPreloadedWarden() {
        constexpr BYTE marker = 0x5a;
        PVOID warden = CreateSimulatedWarden(marker);
        if (warden == nullptr) {
            return false;
        }

        DetectorApi detector;
        bool loaded = LoadDetector(detector);
        bool ready = loaded && detector.waitForReady(10000) != FALSE;
        bool dumped = ready && HasValidDump(warden, marker);
        bool shutdown = loaded && ShutdownDetector(detector);

        VirtualFree(warden, 0, MEM_RELEASE);
        return loaded && ready && dumped && shutdown;
    }

    bool TestHookedWarden() {
        DetectorApi detector;
        bool loaded = LoadDetector(detector);
        bool ready = loaded && detector.waitForReady(10000) != FALSE;
        if (!ready) {
            if (loaded) {
                ShutdownDetector(detector);
            }
            return false;
        }

        constexpr BYTE marker = 0xa5;
        PVOID warden = CreateSimulatedWarden(marker);
        PVOID executableDecoy = CreateExecutableDecoy();
        bool simulationSucceeded = warden != nullptr && executableDecoy != nullptr;

        // Shutdown осушает scan-очередь; дамп выполняется этим же worker'ом.
        bool shutdown = ShutdownDetector(detector);
        bool dumped = shutdown && simulationSucceeded && HasValidDump(warden, marker);
        bool decoyRejected = shutdown && executableDecoy != nullptr && !HasDump(executableDecoy);

        if (warden != nullptr) {
            VirtualFree(warden, 0, MEM_RELEASE);
        }
        if (executableDecoy != nullptr) {
            VirtualFree(executableDecoy, 0, MEM_RELEASE);
        }

        return simulationSucceeded && dumped && decoyRejected && shutdown;
    }
}

int main(int argc, char* argv[]) {
    const bool nonInteractive = argc > 1 && std::string(argv[1]) == "--no-wait";
    std::wcout << L"=== Warden Detector Test Application (x86) ===\n";

    bool preloadedPassed = TestPreloadedWarden();
    bool hookedPassed = TestHookedWarden();
    std::wcout << (preloadedPassed ? L"[+]" : L"[-]")
               << L" Preloaded Warden scenario.\n";
    std::wcout << (hookedPassed ? L"[+]" : L"[-]")
               << L" Hooked Warden scenario.\n";

    std::wcout << L"[+] Warden detector smoke-test completed.\n";
    if (!nonInteractive) {
        std::wcout << L"Press Enter to exit...";
        std::cin.get();
    }

    return preloadedPassed && hookedPassed ? 0 : 1;
}
