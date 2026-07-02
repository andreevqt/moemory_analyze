#include <windows.h>
#include <iostream>
#include <string>
#include "ManualMapSim.h"
#include "../src/Logger.h"

using MemoryAnalyzerShutdownFn = BOOL(WINAPI*)();

// Прототип функции инициализации хуков и сканера из нашей DLL
// Мы можем загрузить нашу DLL динамически через LoadLibrary, чтобы протестировать ее работу.
int main(int argc, char* argv[]) {
    const bool nonInteractive = (argc > 1 && std::string(argv[1]) == "--no-wait");

    std::wcout << L"=== Memory Analyzer Test Application (x86) ===\n";

    // Инициализируем логгер для консоли/теста
    Logger::Initialize(L"test_app.log");
    Logger::Log(L"[Test] Test application started.");

    // 1. Загружаем нашу DLL анализатора памяти (она автоматически установит хуки и запустит сканер)
    std::wcout << L"[+] Loading Memory Analyzer DLL...\n";
    HMODULE hAnalyzer = LoadLibraryW(L"MemoryAnalyzer.dll");
    if (!hAnalyzer) {
        std::wcout << L"[-] Error: Failed to load MemoryAnalyzer.dll. Make sure it is compiled as x86 and placed in the same directory.\n";
        return 1;
    }
    std::wcout << L"[+] Memory Analyzer DLL loaded successfully.\n";

    // Даем немного времени фоновому потоку инициализироваться и провести первичное сканирование
    Sleep(1000);

    // 2. Симулируем ручной маппинг PE-файла.
    // В качестве подопытного PE-файла мы можем использовать саму эту запущенную программу (test_app.exe)
    // или любой другой системный x86 PE-файл (например, c:\windows\syswow64\notepad.exe).
    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);

    std::wcout << L"[+] Simulating manual mapping of: " << currentExePath << L"\n";
    PVOID mappedBase = ManualMapSim::SimulateManualMap(currentExePath);

    if (mappedBase) {
        std::wcout << L"[+] Manual mapping simulation succeeded at address: 0x" << std::hex << (uintptr_t)mappedBase << L"\n";
        std::wcout << L"[+] Waiting for the analyzer to detect and dump the module...\n";

        // Даем время сканеру обнаружить изменение прав доступа (VirtualProtect) и сделать дамп
        Sleep(3000);
    } else {
        std::wcout << L"[-] Error: Manual mapping simulation failed.\n";
    }

    if (mappedBase) {
        VirtualFree(mappedBase, 0, MEM_RELEASE);
        std::wcout << L"[+] Released simulated manual mapping memory.\n";
    }

    // Останавливаем фоновые потоки и снимаем хуки до входа в loader lock.
    auto shutdownAnalyzer = reinterpret_cast<MemoryAnalyzerShutdownFn>(
        GetProcAddress(hAnalyzer, "MemoryAnalyzerShutdown"));
    if (!shutdownAnalyzer || !shutdownAnalyzer()) {
        std::wcout << L"[-] Error: Failed to shut down Memory Analyzer DLL.\n";
        return 1;
    }

    // Выгружаем DLL только после явной очистки ресурсов.
    std::wcout << L"[+] Unloading Memory Analyzer DLL...\n";
    if (!FreeLibrary(hAnalyzer)) {
        std::wcout << L"[-] Error: Failed to unload MemoryAnalyzer.dll.\n";
        return 1;
    }

    std::wcout << L"[+] Test finished. Check 'memory_analyzer.log' and 'test_app.log' for details.\n";
    if (!nonInteractive) {
        std::wcout << L"Press Enter to exit...";
        std::cin.get();
    }

    return mappedBase ? 0 : 1;
}
