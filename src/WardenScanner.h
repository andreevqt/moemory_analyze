#pragma once

#include <windows.h>

namespace WardenScanner {
    bool Initialize();
    void Run();
    void Shutdown();

    // Ставит адрес изменённой секции в очередь единственного worker-потока.
    void QueueScan(PVOID address);

    // Выполняет полный обход в текущем worker-потоке.
    void PerformFullScan();
}
