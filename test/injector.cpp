#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <stdexcept>

// Функция для поиска PID процесса по его имени
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (processName == pe.szExeFile) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

// Функция для чтения логов из именованного канала
void PipeServerThread() {
    // Создаем именованный канал для приема логов от DLL
    HANDLE hPipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\MemoryAnalyzerPipe",
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        1024 * 16,
        1024 * 16,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Error: Failed to create named pipe. Error code: " << GetLastError() << L"\n";
        return;
    }

    std::wcout << L"[+] Named pipe created. Waiting for DLL connection...\n";

    // Ожидаем подключения от DLL
    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        std::wcout << L"[+] DLL connected to pipe! Streaming logs:\n\n";

        wchar_t buffer[4096];
        DWORD bytesRead;

        while (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
            // Гарантируем наличие нуль-терминатора
            buffer[bytesRead / sizeof(wchar_t)] = L'\0';
            std::wcout << buffer << std::endl;
        }
    }

    std::wcout << L"\n[+] Pipe connection closed.\n";
    CloseHandle(hPipe);
}

// Функция для выполнения классической DLL-инжекции через CreateRemoteThread
bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
    std::wcout << L"[+] Opening target process (PID: " << pid << L")...\n";

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"[-] Error: Failed to open target process. Error code: " << GetLastError() << L"\n";
        return false;
    }

    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    std::wcout << L"[+] Allocating memory in target process...\n";
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::wcout << L"[-] Error: Failed to allocate memory in target process. Error code: " << GetLastError() << L"\n";
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Writing DLL path to target process memory...\n";
    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcout << L"[-] Error: Failed to write memory in target process. Error code: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        std::wcout << L"[-] Error: Failed to get address of LoadLibraryW. Error code: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Creating remote thread in target process...\n";
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread) {
        std::wcout << L"[-] Error: Failed to create remote thread. Error code: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Waiting for remote thread to finish...\n";
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        std::wcout << L"[-] Error: LoadLibraryW failed inside target process.\n";
    } else {
        std::wcout << L"[+] DLL successfully injected! Remote HMODULE: 0x" << std::hex << exitCode << L"\n";
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exitCode != 0;
}

int main(int argc, char* argv[]) {
    std::wcout << L"=== Memory Analyzer DLL Injector (x86) ===\n";

    if (argc < 3) {
        std::wcout << L"Usage:\n";
        std::wcout << L"  1. By Process Name: Injector.exe --name <process_name.exe> <path_to_dll>\n";
        std::wcout << L"  2. By Process ID:   Injector.exe --pid <process_id> <path_to_dll>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string target = argv[2];
    std::string dllPathArg = (argc >= 4) ? argv[3] : "";

    if (dllPathArg.empty()) {
        std::wcout << L"[-] Error: Path to DLL is missing.\n";
        return 1;
    }

    // Корректное преобразование UTF-8/ANSI строки в широкую (wchar_t) строку.
    // Посимвольное копирование через begin()/end() ломает не-ASCII символы.
    int wlen = MultiByteToWideChar(CP_ACP, 0, dllPathArg.c_str(), -1, NULL, 0);
    if (wlen <= 0) {
        std::wcout << L"[-] Error: Failed to convert DLL path to wide string.\n";
        return 1;
    }
    std::wstring dllPath(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, dllPathArg.c_str(), -1, &dllPath[0], wlen);

    wchar_t fullDllPath[MAX_PATH];
    if (GetFullPathNameW(dllPath.c_str(), MAX_PATH, fullDllPath, NULL) == 0) {
        std::wcout << L"[-] Error: Failed to resolve absolute path for DLL.\n";
        return 1;
    }

    DWORD pid = 0;
    if (mode == "--name") {
        // Аналогичное корректное преобразование для имени процесса.
        int wlenName = MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, NULL, 0);
        if (wlenName <= 0) {
            std::wcout << L"[-] Error: Failed to convert process name to wide string.\n";
            return 1;
        }
        std::wstring processName(wlenName - 1, L'\0');
        MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, &processName[0], wlenName);

        std::wcout << L"[+] Searching for process: " << processName << L"\n";
        pid = GetProcessIdByName(processName);
        if (pid == 0) {
            std::wcout << L"[-] Error: Process not found.\n";
            return 1;
        }
        std::wcout << L"[+] Found process PID: " << pid << L"\n";
    } else if (mode == "--pid") {
        // std::stoul выбрасывает исключение при некорректном вводе — обрабатываем.
        try {
            pid = std::stoul(target);
        } catch (const std::invalid_argument&) {
            std::wcout << L"[-] Error: Invalid PID value (not a number): " << target.c_str() << L"\n";
            return 1;
        } catch (const std::out_of_range&) {
            std::wcout << L"[-] Error: PID value out of range: " << target.c_str() << L"\n";
            return 1;
        }
    } else {
        std::wcout << L"[-] Error: Invalid mode. Use --name or --pid.\n";
        return 1;
    }

    // Запускаем поток сервера именованного канала для приема логов
    std::thread pipeThread(PipeServerThread);

    // Даем серверу немного времени на запуск перед инжекцией
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (InjectDLL(pid, fullDllPath)) {
        std::wcout << L"[+] Injection completed successfully. Waiting for logs...\n";
        // Ожидаем завершения потока чтения логов
        if (pipeThread.joinable()) {
            pipeThread.join();
        }
        return 0;
    } else {
        std::wcout << L"[-] Injection failed.\n";
        if (pipeThread.joinable()) {
            // В случае ошибки закрываем поток принудительно (или он завершится сам по таймауту/закрытию)
            // Для простоты мы можем просто отсоединить его
            pipeThread.detach();
        }
        return 1;
    }
}
