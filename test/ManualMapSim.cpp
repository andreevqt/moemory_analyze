#include "ManualMapSim.h"
#include "../src/Logger.h"
#include <fstream>
#include <sstream>
#include <vector>

namespace ManualMapSim {

    std::wstring ToHex(uintptr_t value) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << value;
        return ss.str();
    }

    PVOID SimulateManualMap(const std::wstring& pePath) {
        Logger::Log(L"[Sim] Simulating manual map for: " + pePath);

        // 1. Читаем файл с диска
        std::ifstream file(pePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            Logger::Log(L"[Sim] Error: Failed to open file: " + pePath);
            return nullptr;
        }

        std::streamsize size = file.tellg();
        if (size <= 0 || size > 256 * 1024 * 1024) {
            Logger::Log(L"[Sim] Error: Invalid or too large file size.");
            return nullptr;
        }
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> fileBuffer(static_cast<size_t>(size));
        if (!file.read((char*)fileBuffer.data(), size)) {
            Logger::Log(L"[Sim] Error: Failed to read file data.");
            return nullptr;
        }

        // 2. Парсим заголовки
        if (fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            Logger::Log(L"[Sim] Error: File is too small for DOS header.");
            return nullptr;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            Logger::Log(L"[Sim] Error: Invalid DOS signature.");
            return nullptr;
        }

        LONG e_lfanew = dosHeader->e_lfanew;
        if (e_lfanew <= 0 || fileBuffer.size() < sizeof(IMAGE_NT_HEADERS) ||
            static_cast<size_t>(e_lfanew) > fileBuffer.size() - sizeof(IMAGE_NT_HEADERS)) {
            Logger::Log(L"[Sim] Error: Invalid e_lfanew.");
            return nullptr;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer.data() + e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            Logger::Log(L"[Sim] Error: Invalid NT signature.");
            return nullptr;
        }

        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            Logger::Log(L"[Sim] Error: Unsupported PE architecture (expected x86 PE32).");
            return nullptr;
        }

        WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        size_t sectionTableEnd = static_cast<size_t>(e_lfanew) + sizeof(IMAGE_NT_HEADERS) +
            static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (numberOfSections == 0 || numberOfSections > 96 || sectionTableEnd > fileBuffer.size()) {
            Logger::Log(L"[Sim] Error: Invalid section table.");
            return nullptr;
        }

        // 3. Выделяем память под образ (SizeOfImage)
        // Сначала выделяем как PAGE_READWRITE, а затем сменим на PAGE_EXECUTE_READWRITE через VirtualProtect,
        // чтобы проверить наш перехватчик VirtualProtect!
        DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        if (sizeOfImage == 0 || sizeOfImage > 0x40000000) {
            Logger::Log(L"[Sim] Error: Invalid SizeOfImage.");
            return nullptr;
        }

        PVOID imageBase = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!imageBase) {
            Logger::Log(L"[Sim] Error: VirtualAlloc failed.");
            return nullptr;
        }

        Logger::Log(L"[Sim] Allocated memory at: " + ToHex((uintptr_t)imageBase) + L" with PAGE_READWRITE");

        // 4. Копируем заголовки
        DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders == 0 || sizeOfHeaders > fileBuffer.size() || sizeOfHeaders > sizeOfImage) {
            Logger::Log(L"[Sim] Error: Invalid SizeOfHeaders.");
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return nullptr;
        }
        memcpy(imageBase, fileBuffer.data(), sizeOfHeaders);

        // 5. Копируем секции с выравниванием по SectionAlignment
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER section = sectionHeader[i];
            if (section.SizeOfRawData > 0) {
                size_t rawEnd = static_cast<size_t>(section.PointerToRawData) + section.SizeOfRawData;
                size_t virtualEnd = static_cast<size_t>(section.VirtualAddress) + section.SizeOfRawData;
                if (rawEnd > fileBuffer.size() || virtualEnd > sizeOfImage) {
                    Logger::Log(L"[Sim] Warning: Section is out of bounds, skipping.");
                    continue;
                }

                PVOID dest = (BYTE*)imageBase + section.VirtualAddress;
                PVOID src = fileBuffer.data() + section.PointerToRawData;
                memcpy(dest, src, section.SizeOfRawData);
                Logger::Log(L"[Sim] Copied section [" + std::wstring(section.Name, section.Name + strnlen((char*)section.Name, 8)) +
                            L"] to RVA " + ToHex(section.VirtualAddress));
            }
        }

        // 6. Меняем права доступа на PAGE_EXECUTE_READWRITE, имитируя завершение маппинга
        DWORD oldProtect;
        if (!VirtualProtect(imageBase, sizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            Logger::Log(L"[Sim] Error: VirtualProtect failed.");
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return nullptr;
        }

        Logger::Log(L"[Sim] Changed memory protection to PAGE_EXECUTE_READWRITE. Manual mapping simulation complete.");
        return imageBase;
    }
}
