#pragma once

#include <windows.h>
#include <string>
#include <mutex>
#include <fstream>
#include <iostream>

namespace Logger {
    inline std::mutex g_LogMutex;
    inline std::wstring g_LogFilePath = L"memory_analyzer.log";
    inline HANDLE g_PipeHandle = INVALID_HANDLE_VALUE;

    inline void ConnectToPipe() {
        std::lock_guard<std::mutex> lock(g_LogMutex);
        // Пытаемся подключиться к именованному каналу, созданному инжектором
        g_PipeHandle = CreateFileW(
            L"\\\\.\\pipe\\MemoryAnalyzerPipe",
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }

    inline void Initialize(const std::wstring& logPath) {
        {
            std::lock_guard<std::mutex> lock(g_LogMutex);
            g_LogFilePath = logPath;
            std::wofstream logFile(g_LogFilePath, std::ios::out | std::ios::trunc);
            if (logFile.is_open()) {
                logFile << L"[+] Memory Analyzer Logger Initialized\n";
            }
        }

        // Подключаемся к каналу инжектора вне блокировки мьютекса логгера,
        // так как ConnectToPipe() сам захватывает g_LogMutex.
        ConnectToPipe();
    }

    inline void Log(const std::wstring& message) {
        std::lock_guard<std::mutex> lock(g_LogMutex);

        // Форматируем время
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeStr[100];
        swprintf_s(timeStr, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        std::wstring formattedMessage = timeStr + message;

        // Запись в файл лога
        std::wofstream logFile(g_LogFilePath, std::ios::out | std::ios::app);
        if (logFile.is_open()) {
            logFile << formattedMessage << L"\n";
        }

        // Отправка в именованный канал инжектора, если он открыт
        if (g_PipeHandle != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            // Записываем строку вместе с завершающим нулем
            DWORD sizeInBytes = (formattedMessage.length() + 1) * sizeof(wchar_t);
            WriteFile(g_PipeHandle, formattedMessage.c_str(), sizeInBytes, &bytesWritten, NULL);
        }
    }

    inline void ClosePipe() {
        std::lock_guard<std::mutex> lock(g_LogMutex);
        if (g_PipeHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(g_PipeHandle);
            g_PipeHandle = INVALID_HANDLE_VALUE;
        }
    }
}
