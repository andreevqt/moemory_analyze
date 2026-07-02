#pragma once

#include <windows.h>
#include <string>

namespace WardenDetector {
    struct ImageInfo {
        PVOID allocationBase;
        SIZE_T allocationSize;
    };

    // Находит BLL2-образ по любому адресу внутри его VirtualAlloc-аллокации.
    bool TryGetImage(PVOID address, ImageInfo& image);

    // Сохраняет сырой снимок аллокации, сохраняя смещения регионов от AllocationBase.
    bool DumpRawImage(const ImageInfo& image, const std::wstring& outputPath);
}
