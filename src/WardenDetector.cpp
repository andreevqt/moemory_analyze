#include "WardenDetector.h"
#include "Logger.h"
#include <array>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <limits>
#include <new>
#include <sstream>
#include <vector>

namespace WardenDetector {
    static constexpr SIZE_T kMaxImageSize = 256 * 1024 * 1024;
    static constexpr std::array<BYTE, 4> kWardenSignature = {'B', 'L', 'L', '2'};

    static bool SafeCopyMemory(void* destination, const void* source, SIZE_T size) {
        __try {
            memcpy(destination, source, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    static bool IsCopyableProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return baseProtect == PAGE_READONLY ||
               baseProtect == PAGE_READWRITE ||
               baseProtect == PAGE_WRITECOPY ||
               baseProtect == PAGE_EXECUTE ||
               baseProtect == PAGE_EXECUTE_READ ||
               baseProtect == PAGE_EXECUTE_READWRITE ||
               baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    static bool IsExecutableProtection(DWORD protect) {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return false;
        }

        DWORD baseProtect = protect & 0xff;
        return baseProtect == PAGE_EXECUTE ||
               baseProtect == PAGE_EXECUTE_READ ||
               baseProtect == PAGE_EXECUTE_READWRITE ||
               baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    static std::wstring ToHex(uintptr_t value) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << value;
        return ss.str();
    }

    bool TryGetImage(PVOID address, ImageInfo& image) {
        image = {};
        if (address == nullptr) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(address, &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || mbi.AllocationBase == nullptr) {
            return false;
        }

        std::array<BYTE, 4> signature = {};
        if (!SafeCopyMemory(signature.data(), mbi.AllocationBase, signature.size()) ||
            signature != kWardenSignature) {
            return false;
        }

        BYTE* allocationBase = static_cast<BYTE*>(mbi.AllocationBase);
        uintptr_t allocationBaseAddress = reinterpret_cast<uintptr_t>(allocationBase);
        uintptr_t currentAddress = allocationBaseAddress;
        SIZE_T allocationSize = 0;
        bool hasExecutableRegion = false;

        while (allocationSize < kMaxImageSize) {
            MEMORY_BASIC_INFORMATION region = {};
            if (VirtualQuery(reinterpret_cast<PVOID>(currentAddress), &region, sizeof(region)) != sizeof(region) ||
                region.AllocationBase != allocationBase || region.RegionSize == 0) {
                break;
            }

            uintptr_t regionAddress = reinterpret_cast<uintptr_t>(region.BaseAddress);
            if (regionAddress < allocationBaseAddress) {
                return false;
            }
            SIZE_T regionOffset = regionAddress - allocationBaseAddress;
            if (regionOffset > kMaxImageSize || region.RegionSize > kMaxImageSize - regionOffset) {
                return false;
            }

            SIZE_T regionEnd = regionOffset + region.RegionSize;
            if (regionEnd <= allocationSize) {
                return false;
            }

            hasExecutableRegion = hasExecutableRegion ||
                (region.State == MEM_COMMIT && IsExecutableProtection(region.Protect));
            allocationSize = regionEnd;
            if (allocationBaseAddress >
                std::numeric_limits<uintptr_t>::max() - allocationSize) {
                return false;
            }
            currentAddress = allocationBaseAddress + allocationSize;
        }

        if (allocationSize == 0 || allocationSize > kMaxImageSize || !hasExecutableRegion) {
            return false;
        }

        image = { allocationBase, allocationSize };
        return true;
    }

    bool DumpRawImage(const ImageInfo& image, const std::wstring& outputPath) {
        if (image.allocationBase == nullptr ||
            image.allocationSize == 0 ||
            image.allocationSize > kMaxImageSize) {
            return false;
        }

        MEMORY_BASIC_INFORMATION allocation = {};
        if (VirtualQuery(image.allocationBase, &allocation, sizeof(allocation)) != sizeof(allocation) ||
            allocation.AllocationBase != image.allocationBase) {
            Logger::Log(L"[Warden] Image is no longer available at " +
                        ToHex(reinterpret_cast<uintptr_t>(image.allocationBase)) + L".");
            return false;
        }

        SIZE_T imageSize = image.allocationSize;
        std::vector<BYTE> rawBuffer;
        try {
            rawBuffer.resize(imageSize, 0);
        } catch (const std::bad_alloc&) {
            Logger::Log(L"[Warden] Failed to allocate raw dump buffer.");
            return false;
        }
        BYTE* allocationBase = static_cast<BYTE*>(image.allocationBase);
        uintptr_t allocationBaseAddress = reinterpret_cast<uintptr_t>(allocationBase);
        SIZE_T offset = 0;

        while (offset < imageSize) {
            MEMORY_BASIC_INFORMATION region = {};
            BYTE* current = allocationBase + offset;
            if (VirtualQuery(current, &region, sizeof(region)) != sizeof(region) ||
                region.AllocationBase != allocationBase || region.RegionSize == 0) {
                break;
            }

            uintptr_t regionAddress = reinterpret_cast<uintptr_t>(region.BaseAddress);
            if (regionAddress < allocationBaseAddress) {
                break;
            }
            SIZE_T regionOffset = regionAddress - allocationBaseAddress;
            if (regionOffset >= imageSize) {
                break;
            }

            SIZE_T copySize = region.RegionSize;
            if (copySize > imageSize - regionOffset) {
                copySize = imageSize - regionOffset;
            }

            if (region.State == MEM_COMMIT && IsCopyableProtection(region.Protect) &&
                !SafeCopyMemory(rawBuffer.data() + regionOffset, region.BaseAddress, copySize)) {
                Logger::Log(L"[Warden] Warning: failed to copy region at " +
                            ToHex(reinterpret_cast<uintptr_t>(region.BaseAddress)) + L".");
            }

            SIZE_T nextOffset = regionOffset + region.RegionSize;
            if (nextOffset <= offset) {
                break;
            }
            offset = nextOffset;
        }

        std::ofstream outFile(outputPath, std::ios::out | std::ios::binary);
        if (!outFile.is_open()) {
            Logger::Log(L"[Warden] Failed to open output file: " + outputPath);
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(rawBuffer.data()),
                      static_cast<std::streamsize>(rawBuffer.size()));
        if (!outFile.good()) {
            Logger::Log(L"[Warden] Failed to write raw image: " + outputPath);
            return false;
        }

        Logger::Log(L"[Warden] Successfully dumped raw image to " + outputPath);
        return true;
    }
}
