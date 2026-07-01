#pragma once

#include <windows.h>
#include <string>

namespace ManualMapSim {
    // Функция, которая симулирует ручной маппинг PE-файла в память текущего процесса.
    // Она считывает указанный PE-файл, выделяет память через VirtualAlloc,
    // копирует заголовки и секции (выравнивая их по SectionAlignment),
    // но НЕ регистрирует модуль в LDR (PEB), имитируя скрытую загрузку.
    PVOID SimulateManualMap(const std::wstring& pePath);
}
