#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <set>

namespace MemoryScanner {
    // Инициализация сканера
    void Initialize();

    // Остановка сканера
    void Shutdown();

    // Добавить адрес в очередь на сканирование
    void QueueScan(PVOID address, SIZE_T size);

    // Выполнить полное сканирование памяти процесса (VirtualQuery)
    void PerformFullScan();
}
