#include <windows.h>
#include "Logger.h"
#include "WardenScanner.h"
#include "HookManager.h"

namespace {
    HANDLE g_MainThread = NULL;
    HANDLE g_ReadyEvent = NULL;
    volatile LONG g_InitializationSucceeded = FALSE;

    void SignalReady(BOOL succeeded) {
        InterlockedExchange(&g_InitializationSucceeded, succeeded);
        if (g_ReadyEvent != NULL) {
            SetEvent(g_ReadyEvent);
        }
    }
}

DWORD WINAPI MainThread(LPVOID) {
    Logger::Initialize(L"warden_detector.log");
    Logger::Log(L"[Main] Warden Detector DLL injected.");

    if (!WardenScanner::Initialize()) {
        Logger::Log(L"[Main] Error: Failed to initialize Warden scanner.");
        SignalReady(FALSE);
        return 1;
    }

    if (HookManager::InitializeHooks()) {
        Logger::Log(L"[Main] VirtualProtect hooks initialized.");
    } else {
        Logger::Log(L"[Main] Error: Failed to initialize hooks.");
        WardenScanner::Shutdown();
        SignalReady(FALSE);
        return 1;
    }

    WardenScanner::PerformFullScan();
    SignalReady(TRUE);
    WardenScanner::Run();

    return 0;
}

extern "C" BOOL WINAPI WardenDetectorWaitForReady(DWORD timeoutMs) {
    if (g_ReadyEvent == NULL) {
        return FALSE;
    }

    DWORD waitResult = WaitForSingleObject(g_ReadyEvent, timeoutMs);
    return waitResult == WAIT_OBJECT_0 &&
           InterlockedCompareExchange(&g_InitializationSucceeded, FALSE, FALSE) != FALSE;
}

extern "C" BOOL WINAPI WardenDetectorShutdown() {
    if (g_ReadyEvent != NULL) {
        WaitForSingleObject(g_ReadyEvent, INFINITE);
    }

    Logger::Log(L"[Main] Shutting down Warden Detector...");
    if (!HookManager::RemoveHooks()) {
        Logger::Log(L"[Main] Shutdown aborted because hooks could not be removed safely.");
        return FALSE;
    }
    WardenScanner::Shutdown();

    if (g_MainThread != NULL) {
        WaitForSingleObject(g_MainThread, INFINITE);
        CloseHandle(g_MainThread);
        g_MainThread = NULL;
    }
    if (g_ReadyEvent != NULL) {
        CloseHandle(g_ReadyEvent);
        g_ReadyEvent = NULL;
    }
    Logger::Log(L"[Main] Cleanup finished. Goodbye.");
    Logger::ClosePipe();
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Отключаем вызовы DLL_THREAD_ATTACH/DETACH для оптимизации
        DisableThreadLibraryCalls(hModule);
        InterlockedExchange(&g_InitializationSucceeded, FALSE);
        g_ReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (g_ReadyEvent == NULL) {
            return FALSE;
        }
        // Создаем фоновый поток для инициализации и работы
        g_MainThread = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        if (g_MainThread == NULL) {
            CloseHandle(g_ReadyEvent);
            g_ReadyEvent = NULL;
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup выполняется через WardenDetectorShutdown до FreeLibrary.
        // Под loader lock нельзя ждать потоки, работать с MinHook или выполнять I/O.
        break;
    }
    return TRUE;
}
