#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace PEDumper {
    // Структура для хранения информации о найденном PE-модуле
    struct PEInfo {
        PVOID baseAddress;
        SIZE_T size;
    };

    // Функция для восстановления PE-структуры из памяти и сохранения на диск
    bool DumpProcessMemory(PVOID baseAddress, const std::wstring& outputPath);

    // Функция для проверки, является ли регион памяти PE-модулем
    bool IsValidPEHeader(PVOID address);
}
