cmake_minimum_required(VERSION 3.15)
project(MemoryAnalyzerProject LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "MemoryAnalyzer supports Windows only")
endif()

# Требуется стандарт C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX)

include(CTest)
include(FetchContent)

# Настройки для MSVC (Visual Studio)
if(MSVC)
    # Отключаем предупреждения о небезопасных функциях (например, swprintf_s, memcpy)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(/W4 /permissive-)
    # Настройка статической линковки рантайма (опционально, для переносимости)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(minhook)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(WARNING "Project is designed for x86 targets. Configure CMake with -A Win32 for Visual Studio generators.")
endif()

# 1. Создание цели для DLL (MemoryAnalyzer)
add_library(MemoryAnalyzer SHARED
    src/MemoryAnalyzer.def
    src/dllmain.cpp
    src/Logger.h
    src/PEDumper.h
    src/PEDumper.cpp
    src/MemoryScanner.h
    src/MemoryScanner.cpp
    src/HookManager.h
    src/HookManager.cpp
)

# Указываем директорию заголовочных файлов для DLL
target_include_directories(MemoryAnalyzer PRIVATE src)
target_link_libraries(MemoryAnalyzer PRIVATE minhook)

# 2. Создание цели для тестового приложения (TestApp)
add_executable(TestApp
    test/test_app.cpp
    test/ManualMapSim.h
    test/ManualMapSim.cpp
    src/PEDumper.cpp # Используем функции валидации PE в тесте
)

# Указываем директории заголовочных файлов для TestApp
target_include_directories(TestApp PRIVATE src test)

add_dependencies(TestApp MemoryAnalyzer)

# Настройка копирования DLL в папку с исполняемым файлом после сборки
add_custom_command(TARGET TestApp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:MemoryAnalyzer>
    $<TARGET_FILE_DIR:TestApp>
)

# 3. Создание цели для инжектора (Injector)
add_executable(Injector
    test/injector.cpp
)

add_dependencies(Injector MemoryAnalyzer)

# Настройка копирования DLL в папку с инжектором после сборки
add_custom_command(TARGET Injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:MemoryAnalyzer>
    $<TARGET_FILE_DIR:Injector>
)

if(BUILD_TESTING)
    add_test(NAME TestAppSmoke COMMAND TestApp --no-wait)
endif()
