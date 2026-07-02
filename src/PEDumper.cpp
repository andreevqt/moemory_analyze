#include "PEDumper.h"
#include "Logger.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace PEDumper {

    // Максимальный размер заголовков и одной секции для защиты от некорректных/вредоносных PE.
    static constexpr DWORD kMaxHeadersSize = 0x10000;      // 64 KB
    static constexpr DWORD kMaxSectionRawSize = 0x4000000; // 64 MB
    static constexpr WORD kMaxSectionCount = 96;

    static bool SafeCopyMemory(void* destination, const void* source, size_t size) {
        __try {
            memcpy(destination, source, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    std::wstring ToHex(uintptr_t value) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << value;
        return ss.str();
    }

    bool IsPowerOfTwo(DWORD value) {
        return value != 0 && (value & (value - 1)) == 0;
    }

    bool IsReasonableFileAlignment(DWORD fileAlignment) {
        return fileAlignment >= 0x200 && fileAlignment <= 0x10000 && IsPowerOfTwo(fileAlignment);
    }

    bool IsValidPEHeader(PVOID address) {
        __try {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)address;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                return false;
            }

            LONG e_lfanew = dosHeader->e_lfanew;
            if (e_lfanew <= 0 || (DWORD)e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
                (DWORD)e_lfanew > kMaxHeadersSize - sizeof(IMAGE_NT_HEADERS) || (e_lfanew & 3) != 0) {
                return false;
            }

            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)address + e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                return false;
            }

            // Дополнительная проверка архитектуры (целевая x86)
            if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
                return false;
            }

            if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                return false;
            }

            WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
            if (numberOfSections == 0 || numberOfSections > kMaxSectionCount) {
                return false;
            }

            DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
            if (sizeOfHeaders == 0 || sizeOfHeaders > kMaxHeadersSize) {
                return false;
            }

            size_t sectionTableEnd = static_cast<size_t>(e_lfanew) + sizeof(IMAGE_NT_HEADERS) +
                static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (sectionTableEnd > sizeOfHeaders) {
                return false;
            }

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool DumpProcessMemory(PVOID baseAddress, const std::wstring& outputPath) {
        Logger::Log(L"[Dumper] Attempting to dump PE at base address: " + ToHex((uintptr_t)baseAddress));

        if (!IsValidPEHeader(baseAddress)) {
            Logger::Log(L"[Dumper] Error: Invalid PE header at " + ToHex((uintptr_t)baseAddress));
            return false;
        }

        IMAGE_DOS_HEADER dosHeader = {};
        if (!SafeCopyMemory(&dosHeader, baseAddress, sizeof(dosHeader))) {
            Logger::Log(L"[Dumper] Error: Failed to read DOS header.");
            return false;
        }

        // Валидация e_lfanew: должен быть положительным, указывать в пределах заголовков
        // и быть выровненным по 4 байта (требование PE-формата).
        LONG e_lfanew = dosHeader.e_lfanew;
        if (e_lfanew <= 0 || (DWORD)e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
            (DWORD)e_lfanew > kMaxHeadersSize - sizeof(IMAGE_NT_HEADERS) || (e_lfanew & 3) != 0) {
            Logger::Log(L"[Dumper] Error: Invalid e_lfanew value: " + std::to_wstring(e_lfanew));
            return false;
        }

        IMAGE_NT_HEADERS ntHeaders = {};
        if (!SafeCopyMemory(&ntHeaders, (BYTE*)baseAddress + e_lfanew, sizeof(ntHeaders))) {
            Logger::Log(L"[Dumper] Error: Failed to read NT headers.");
            return false;
        }

        WORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
            ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
            numberOfSections == 0 || numberOfSections > kMaxSectionCount) {
            Logger::Log(L"[Dumper] Error: PE headers changed during validation.");
            return false;
        }

        DWORD sizeOfImage = ntHeaders.OptionalHeader.SizeOfImage;
        if (sizeOfImage == 0 || sizeOfImage > 0x40000000) { // Не более 1 GB
            Logger::Log(L"[Dumper] Error: Invalid SizeOfImage: " + std::to_wstring(sizeOfImage));
            return false;
        }

        // 1. Копируем заголовки PE в стабильный локальный снимок.
        DWORD sizeOfHeaders = ntHeaders.OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders == 0 || sizeOfHeaders > kMaxHeadersSize) {
            Logger::Log(L"[Dumper] Error: Invalid SizeOfHeaders: " + std::to_wstring(sizeOfHeaders));
            return false;
        }
        if (sizeOfHeaders > sizeOfImage) {
            Logger::Log(L"[Dumper] Error: SizeOfHeaders exceeds SizeOfImage.");
            return false;
        }
        size_t sectionTableEnd = static_cast<size_t>(e_lfanew) + sizeof(IMAGE_NT_HEADERS) +
            static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableEnd > sizeOfHeaders) {
            Logger::Log(L"[Dumper] Error: Section table exceeds SizeOfHeaders.");
            return false;
        }

        std::vector<BYTE> rawBuffer(sizeOfHeaders);
        if (!SafeCopyMemory(rawBuffer.data(), baseAddress, sizeOfHeaders)) {
            Logger::Log(L"[Dumper] Error: Failed to read PE headers.");
            return false;
        }

        PIMAGE_DOS_HEADER outDosHeader = (PIMAGE_DOS_HEADER)rawBuffer.data();
        PIMAGE_NT_HEADERS outNtHeaders = (PIMAGE_NT_HEADERS)(rawBuffer.data() + e_lfanew);
        if (outDosHeader->e_magic != IMAGE_DOS_SIGNATURE || outDosHeader->e_lfanew != e_lfanew ||
            memcmp(outNtHeaders, &ntHeaders, sizeof(ntHeaders)) != 0) {
            Logger::Log(L"[Dumper] Error: PE headers changed while being copied.");
            return false;
        }

        DWORD fileAlign = outNtHeaders->OptionalHeader.FileAlignment;
        std::vector<IMAGE_SECTION_HEADER> sections(numberOfSections);
        memcpy(sections.data(), IMAGE_FIRST_SECTION(outNtHeaders),
               static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER));

        // 2. Копируем секции с восстановлением выравнивания (Alignment Fix)
        Logger::Log(L"[Dumper] Number of sections: " + std::to_wstring(numberOfSections));

        for (WORD i = 0; i < numberOfSections; ++i) {
            IMAGE_SECTION_HEADER section = sections[i];

            // Адрес секции в памяти (RVA)
            DWORD virtualAddress = section.VirtualAddress;
            // Размер секции в памяти
            DWORD virtualSize = section.Misc.VirtualSize;
            // Размер секции на диске (выровненный)
            DWORD sizeOfRawData = section.SizeOfRawData;

            Logger::Log(L"[Dumper] Section [" + std::wstring(section.Name, section.Name + strnlen((char*)section.Name, 8)) +
                        L"] RVA: " + ToHex(virtualAddress) +
                        L", VirtualSize: " + ToHex(virtualSize) +
                        L", SizeOfRawData: " + ToHex(sizeOfRawData));

            if (virtualSize == 0) continue;

            // Вычисляем новое смещение на диске (RawAddress)
            // Для восстановления выравнивания мы можем использовать FileAlignment или просто последовательно записывать секции.
            // Чтобы PE-файл был максимально валидным, мы выравниваем PointerToRawData по FileAlignment.
            if (!IsReasonableFileAlignment(fileAlign)) {
                Logger::Log(L"[Dumper] Error: Invalid FileAlignment: " + std::to_wstring(fileAlign));
                return false;
            }

            // Если SizeOfRawData некорректен (например, меньше VirtualSize из-за оптимизаций маппера),
            // выравниваем VirtualSize по FileAlignment для дискового представления.
            DWORD newSizeOfRawData = virtualSize;
            if (newSizeOfRawData % fileAlign != 0) {
                newSizeOfRawData = ((newSizeOfRawData / fileAlign) + 1) * fileAlign;
            }

            // Защита от некорректных/вредоносных PE с огромным VirtualSize (например, .bss).
            if (newSizeOfRawData > kMaxSectionRawSize) {
                Logger::Log(L"[Dumper] Warning: Section VirtualSize too large (" + std::to_wstring(newSizeOfRawData) +
                            L"), clamping to " + std::to_wstring(kMaxSectionRawSize));
                newSizeOfRawData = kMaxSectionRawSize;
            }

            // Проверяем, что секция не выходит за пределы образа до изменения выходного заголовка.
            if (virtualAddress >= sizeOfImage || newSizeOfRawData > sizeOfImage - virtualAddress) {
                Logger::Log(L"[Dumper] Warning: Section exceeds SizeOfImage, skipping.");
                continue;
            }

            DWORD currentRawOffset = static_cast<DWORD>(rawBuffer.size());

            // Выравниваем текущий размер буфера по FileAlignment
            if (currentRawOffset % fileAlign != 0) {
                DWORD padding = fileAlign - (currentRawOffset % fileAlign);
                rawBuffer.insert(rawBuffer.end(), padding, 0);
                currentRawOffset = static_cast<DWORD>(rawBuffer.size());
            }

            // Обновляем заголовок секции в буфере только после полной валидации.
            outNtHeaders = (PIMAGE_NT_HEADERS)(rawBuffer.data() + e_lfanew);
            PIMAGE_SECTION_HEADER outSectionHeader = IMAGE_FIRST_SECTION(outNtHeaders);
            outSectionHeader[i].PointerToRawData = currentRawOffset;
            outSectionHeader[i].SizeOfRawData = newSizeOfRawData;

            // Выделяем место в буфере под данные секции
            rawBuffer.insert(rawBuffer.end(), newSizeOfRawData, 0);

            // Копируем данные секции из памяти процесса в буфер
            PVOID sectionMemoryAddress = (BYTE*)baseAddress + virtualAddress;

            if (!SafeCopyMemory(rawBuffer.data() + currentRawOffset, sectionMemoryAddress,
                                std::min(virtualSize, newSizeOfRawData))) {
                Logger::Log(L"[Dumper] Warning: Failed to read section memory at " + ToHex((uintptr_t)sectionMemoryAddress));
            }
        }

        // Записываем буфер в файл
        std::ofstream outFile(outputPath, std::ios::out | std::ios::binary);
        if (!outFile.is_open()) {
            Logger::Log(L"[Dumper] Error: Failed to open output file: " + outputPath);
            return false;
        }

        outFile.write((char*)rawBuffer.data(), static_cast<std::streamsize>(rawBuffer.size()));
        outFile.close();

        Logger::Log(L"[Dumper] Successfully dumped PE to " + outputPath);
        return true;
    }
}
