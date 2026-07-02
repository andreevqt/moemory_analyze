#include <windows.h>
#include "Logger.h"
#include "MemoryScanner.h"
#include "HookManager.h"

namespace {
    HANDLE g_MainThread = NULL;
}

DWORD WINAPI MainThread(LPVOID) {
    // Инициализируем логгер
    Logger::Initialize(L"memory_analyzer.log");
    Logger::Log(L"[Main] Memory Analyzer DLL Injected.");

    // Инициализируем асинхронный сканер памяти
    MemoryScanner::Initialize();

    // Устанавливаем хуки на VirtualAlloc/VirtualProtect
    if (HookManager::InitializeHooks()) {
        Logger::Log(L"[Main] Hooks successfully initialized.");
    } else {
        Logger::Log(L"[Main] Error: Failed to initialize hooks.");
    }

    // Выполняем первичное сканирование памяти для обнаружения уже загруженных модулей
    MemoryScanner::PerformFullScan();

    return 0;
}

extern "C" BOOL WINAPI MemoryAnalyzerShutdown() {
    if (g_MainThread != NULL) {
        WaitForSingleObject(g_MainThread, INFINITE);
        CloseHandle(g_MainThread);
        g_MainThread = NULL;
    }

    Logger::Log(L"[Main] Shutting down Memory Analyzer...");
    HookManager::RemoveHooks();
    MemoryScanner::Shutdown();
    Logger::Log(L"[Main] Cleanup finished. Goodbye.");
    Logger::ClosePipe();
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Отключаем вызовы DLL_THREAD_ATTACH/DETACH для оптимизации
        DisableThreadLibraryCalls(hModule);
        // Создаем фоновый поток для инициализации и работы
        g_MainThread = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        if (g_MainThread == NULL) {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup выполняется через MemoryAnalyzerShutdown до FreeLibrary.
        // Под loader lock нельзя ждать потоки, работать с MinHook или выполнять I/O.
        break;
    }
    return TRUE;
}
