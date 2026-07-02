#include "MemoryScanner.h"
#include "PEDumper.h"
#include "Logger.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>

namespace MemoryScanner {
    struct ScanRequest {
        PVOID address;
        SIZE_T size;
    };

    std::queue<ScanRequest> g_ScanQueue;
    std::mutex g_QueueMutex;
    std::condition_variable g_QueueCV;
    std::thread g_WorkerThread;
    bool g_ShouldStop = false;

    // Множество уже сдампленных базовых адресов, чтобы избежать дубликатов
    std::set<PVOID> g_DumpedModules;
    std::mutex g_DumpedMutex;

    // Потокобезопасное форматирование времени (std::localtime возвращает указатель
    // на общий статический буфер, что приводит к гонке данных).
    std::wstring FormatTimestamp(std::time_t in_time_t) {
        std::tm tm_buf;
        localtime_s(&tm_buf, &in_time_t);
        std::wstringstream ss;
        ss << std::put_time(&tm_buf, L"%Y%m%d_%H%M%S");
        return ss.str();
    }

    std::wstring GetDumpFilename(PVOID baseAddress) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        std::wstringstream ss;
        ss << L"dump_" << std::hex << (uintptr_t)baseAddress << L"_"
           << FormatTimestamp(in_time_t) << L".exe";
        return ss.str();
    }

    // Вспомогательная функция для единообразного hex-форматирования адресов в логах
    std::wstring AddrToHex(uintptr_t addr) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << addr;
        return ss.str();
    }

    bool IsReadableProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return (baseProtect == PAGE_READONLY ||
                baseProtect == PAGE_READWRITE ||
                baseProtect == PAGE_WRITECOPY ||
                baseProtect == PAGE_EXECUTE_READ ||
                baseProtect == PAGE_EXECUTE_READWRITE ||
                baseProtect == PAGE_EXECUTE_WRITECOPY);
    }

    bool IsInterestingProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return (baseProtect == PAGE_READWRITE ||
                baseProtect == PAGE_EXECUTE ||
                baseProtect == PAGE_EXECUTE_READ ||
                baseProtect == PAGE_EXECUTE_READWRITE ||
                baseProtect == PAGE_EXECUTE_WRITECOPY);
    }

    void WorkerProc() {
        Logger::Log(L"[Scanner] Worker thread started.");
        while (true) {
            ScanRequest req;
            {
                std::unique_lock<std::mutex> lock(g_QueueMutex);
                g_QueueCV.wait(lock, [] { return !g_ScanQueue.empty() || g_ShouldStop; });

                if (g_ShouldStop && g_ScanQueue.empty()) {
                    break;
                }

                req = g_ScanQueue.front();
                g_ScanQueue.pop();
            }

            // Проверяем, не дампили ли мы уже этот адрес
            {
                std::lock_guard<std::mutex> lock(g_DumpedMutex);
                if (g_DumpedModules.count(req.address) > 0) {
                    continue;
                }
            }

            // Проверяем, есть ли PE-заголовок по указанному адресу.
            // IsValidPEHeader защищает чтение памяти через SEH внутри POD-функции.
            if (PEDumper::IsValidPEHeader(req.address)) {
                {
                    std::lock_guard<std::mutex> lock(g_DumpedMutex);
                    g_DumpedModules.insert(req.address);
                }

                std::wstring filename = GetDumpFilename(req.address);
                Logger::Log(L"[Scanner] Found PE module at " + AddrToHex((uintptr_t)req.address) + L"! Dumping...");
                PEDumper::DumpProcessMemory(req.address, filename);
            } else {
                // Если адрес не указывает прямо на PE, но размер большой, попробуем найти MZ внутри региона
                // (например, если хук сработал на VirtualAlloc, который выделил память, а MZ записали чуть позже)
                // Для этого мы можем подождать короткое время или сканировать регион с шагом страницы (4KB)
                BYTE* start = (BYTE*)req.address;
                SIZE_T scanSize = req.size;

                // Ограничим размер сканирования для безопасности
                if (scanSize > 100 * 1024 * 1024) { // 100 MB limit
                    scanSize = 100 * 1024 * 1024;
                }

                for (SIZE_T offset = 0; offset < scanSize; offset += 0x1000) {
                    PVOID currentAddr = start + offset;

                    // Перепроверяем доступность страницы через VirtualQuery перед чтением,
                    // так как регион мог быть освобождён между постановкой в очередь и сканированием.
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery(currentAddr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                        continue;
                    }
                    if (mbi.State != MEM_COMMIT || !IsReadableProtection(mbi.Protect)) {
                        continue;
                    }

                    if (PEDumper::IsValidPEHeader(currentAddr)) {
                        bool alreadyDumped = false;
                        {
                            std::lock_guard<std::mutex> lock(g_DumpedMutex);
                            if (g_DumpedModules.count(currentAddr) > 0) {
                                alreadyDumped = true;
                            } else {
                                g_DumpedModules.insert(currentAddr);
                            }
                        }

                        if (!alreadyDumped) {
                            std::wstring filename = GetDumpFilename(currentAddr);
                            Logger::Log(L"[Scanner] Found PE module inside region at " + AddrToHex((uintptr_t)currentAddr) + L"! Dumping...");
                            PEDumper::DumpProcessMemory(currentAddr, filename);
                            break;
                        }
                    }
                }
            }
        }
        Logger::Log(L"[Scanner] Worker thread stopped.");
    }

    void Initialize() {
        // Очищаем глобальное состояние на случай повторной инициализации
        // (DLL может быть выгружена и загружена заново в том же процессе).
        {
            std::lock_guard<std::mutex> lock(g_QueueMutex);
            std::queue<ScanRequest> empty;
            std::swap(g_ScanQueue, empty);
            g_ShouldStop = false;
        }
        {
            std::lock_guard<std::mutex> lock(g_DumpedMutex);
            g_DumpedModules.clear();
        }
        g_WorkerThread = std::thread(WorkerProc);
    }

    void Shutdown() {
        {
            std::lock_guard<std::mutex> lock(g_QueueMutex);
            g_ShouldStop = true;
        }
        g_QueueCV.notify_all();
        if (g_WorkerThread.joinable()) {
            g_WorkerThread.join();
        }
    }

    void QueueScan(PVOID address, SIZE_T size) {
        if (address == nullptr || size == 0) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_QueueMutex);
            if (g_ShouldStop) {
                return;
            }
            g_ScanQueue.push({ address, size });
        }
        g_QueueCV.notify_one();
    }

    void PerformFullScan() {
        Logger::Log(L"[Scanner] Starting full memory scan...");
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = si.lpMinimumApplicationAddress;

        while (address < si.lpMaximumApplicationAddress) {
            if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Нас интересует выделенная (Commit) память с правами на исполнение или чтение/запись.
                // Модификаторы PAGE_GUARD/PAGE_NOACCESS исключаем до чтения заголовков.
                if (mbi.State == MEM_COMMIT && IsInterestingProtection(mbi.Protect)) {

                    // Проверяем на наличие PE-заголовка
                    if (PEDumper::IsValidPEHeader(mbi.BaseAddress)) {
                        QueueScan(mbi.BaseAddress, mbi.RegionSize);
                    }
                }
                address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
            } else {
                address = (LPVOID)((DWORD_PTR)address + 0x1000);
            }
        }
        Logger::Log(L"[Scanner] Full memory scan completed.");
    }
}
