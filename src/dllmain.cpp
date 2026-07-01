#include <windows.h>
#include "Logger.h"
#include "MemoryScanner.h"
#include "HookManager.h"

DWORD WINAPI MainThread(LPVOID lpParam) {
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

    // Оставляем поток активным, пока DLL не будет выгружена
    // В реальном сценарии здесь может быть цикл ожидания или обработка сигналов
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Отключаем вызовы DLL_THREAD_ATTACH/DETACH для оптимизации
        DisableThreadLibraryCalls(hModule);
        // Создаем фоновый поток для инициализации и работы
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        // ВНИМАНИЕ: При выгрузке DLL во время завершения процесса (lpReserved != NULL)
        // загрузчик удерживает критическую секцию (loader lock). Выполнение сложных
        // операций (I/O, ожидание потоков, работа с кучей) может привести к дедлоку.
        // Поэтому безопасно очищаем ресурсы только при ручной выгрузке (lpReserved == NULL).
        if (lpReserved == NULL) {
            Logger::Log(L"[Main] DLL_PROCESS_DETACH (manual unload). Cleaning up...");
            HookManager::RemoveHooks();
            MemoryScanner::Shutdown();
            Logger::Log(L"[Main] Cleanup finished. Goodbye.");
            Logger::ClosePipe();
        } else {
            // Процесс завершается — просто снимаем хуки, не дожидаясь потока сканера,
            // чтобы не рисковать дедлоком на loader lock.
            HookManager::RemoveHooks();
            // Не вызываем MemoryScanner::Shutdown() и Logger::ClosePipe(),
            // так как они могут заблокироваться на I/O или join потока.
        }
        break;
    }
    return TRUE;
}
