#include "WardenScanner.h"
#include "Logger.h"
#include "WardenDetector.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <queue>
#include <sstream>

namespace WardenScanner {
    std::queue<PVOID> g_ScanQueue;
    std::mutex g_ScanMutex;
    std::condition_variable g_ScanCV;
    bool g_Initialized = false;
    bool g_ShouldStop = false;
    std::atomic<bool> g_WardenDumped = false;

    std::wstring FormatTimestamp(std::time_t timestamp) {
        std::tm localTime = {};
        localtime_s(&localTime, &timestamp);
        std::wstringstream stream;
        stream << std::put_time(&localTime, L"%Y%m%d_%H%M%S");
        return stream.str();
    }

    std::wstring GetDumpFilename(PVOID baseAddress) {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::system_clock::to_time_t(now);

        std::wstringstream stream;
        stream << L"warden_" << std::hex << reinterpret_cast<uintptr_t>(baseAddress)
               << L"_" << FormatTimestamp(timestamp) << L".bin";
        return stream.str();
    }

    std::wstring ToHex(uintptr_t value) {
        std::wstringstream stream;
        stream << L"0x" << std::hex << value;
        return stream.str();
    }

    bool IsExecutableProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return baseProtect == PAGE_EXECUTE ||
               baseProtect == PAGE_EXECUTE_READ ||
               baseProtect == PAGE_EXECUTE_READWRITE ||
               baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    void ScanAddress(PVOID address) {
        if (g_WardenDumped.load(std::memory_order_acquire)) {
            return;
        }

        WardenDetector::ImageInfo image = {};
        if (!WardenDetector::TryGetImage(address, image)) {
            return;
        }

        std::wstring outputPath = GetDumpFilename(image.allocationBase);
        Logger::Log(L"[Scanner] Detected BLL2 Warden image at " +
                    ToHex(reinterpret_cast<uintptr_t>(image.allocationBase)) +
                    L", size " + ToHex(image.allocationSize) + L"; dumping now.");

        if (WardenDetector::DumpRawImage(image, outputPath)) {
            g_WardenDumped.store(true, std::memory_order_release);
        } else {
            Logger::Log(L"[Scanner] Failed to dump detected Warden image.");
        }
    }

    void ScanFullProcess() {
        Logger::Log(L"[Scanner] Starting full Warden scan...");

        SYSTEM_INFO systemInfo = {};
        GetSystemInfo(&systemInfo);

        DWORD_PTR address = reinterpret_cast<DWORD_PTR>(systemInfo.lpMinimumApplicationAddress);
        DWORD_PTR maximumAddress = reinterpret_cast<DWORD_PTR>(systemInfo.lpMaximumApplicationAddress);
        while (address < maximumAddress && !g_WardenDumped.load(std::memory_order_acquire)) {
            MEMORY_BASIC_INFORMATION region = {};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) == sizeof(region)) {
                if (region.State == MEM_COMMIT && IsExecutableProtection(region.Protect)) {
                    ScanAddress(region.BaseAddress);
                }

                DWORD_PTR nextAddress = reinterpret_cast<DWORD_PTR>(region.BaseAddress) + region.RegionSize;
                address = nextAddress > address ? nextAddress : address + 0x1000;
            } else {
                address += 0x1000;
            }
        }

        Logger::Log(L"[Scanner] Full Warden scan completed.");
    }

    bool Initialize() {
        std::lock_guard<std::mutex> lock(g_ScanMutex);
        if (g_Initialized) {
            return true;
        }

        std::queue<PVOID> empty;
        std::swap(g_ScanQueue, empty);
        g_ShouldStop = false;
        g_WardenDumped.store(false, std::memory_order_release);
        g_Initialized = true;
        Logger::Log(L"[Scanner] Initialized one worker for detection and dumping.");
        return true;
    }

    void Run() {
        Logger::Log(L"[Scanner] Worker started.");
        while (true) {
            PVOID address = nullptr;
            {
                std::unique_lock<std::mutex> lock(g_ScanMutex);
                g_ScanCV.wait(lock, [] { return !g_ScanQueue.empty() || g_ShouldStop; });
                if (g_ShouldStop && g_ScanQueue.empty()) {
                    break;
                }

                address = g_ScanQueue.front();
                g_ScanQueue.pop();
            }
            ScanAddress(address);
        }
        Logger::Log(L"[Scanner] Worker stopped.");
    }

    void Shutdown() {
        {
            std::lock_guard<std::mutex> lock(g_ScanMutex);
            g_ShouldStop = true;
        }
        g_ScanCV.notify_all();
    }

    void QueueScan(PVOID address) {
        if (address == nullptr || g_WardenDumped.load(std::memory_order_acquire)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_ScanMutex);
            if (!g_Initialized || g_ShouldStop ||
                g_WardenDumped.load(std::memory_order_relaxed)) {
                return;
            }
            g_ScanQueue.push(address);
        }
        g_ScanCV.notify_one();
    }

    void PerformFullScan() {
        ScanFullProcess();
    }
}
