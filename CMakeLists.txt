cmake_minimum_required(VERSION 3.15)
project(WardenDetectorProject LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "WardenDetector supports Windows only")
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

# 1. Warden-only DLL
add_library(WardenDetector SHARED
    src/WardenDetector.def
    src/dllmain.cpp
    src/Logger.h
    src/BoundedUniqueQueue.h
    src/HookCallTracker.h
    src/WardenDetector.h
    src/WardenDetector.cpp
    src/WardenScanner.h
    src/WardenScanner.cpp
    src/HookManager.h
    src/HookManager.cpp
)

target_include_directories(WardenDetector PRIVATE src)
target_link_libraries(WardenDetector PRIVATE minhook)

# 2. Создание цели для тестового приложения (TestApp)
add_executable(TestApp
    test/test_app.cpp
)

add_dependencies(TestApp WardenDetector)

# Настройка копирования DLL в папку с исполняемым файлом после сборки
add_custom_command(TARGET TestApp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:WardenDetector>
    $<TARGET_FILE_DIR:TestApp>
)

# 3. Создание цели для инжектора (Injector)
add_executable(Injector
    test/injector.cpp
)

add_dependencies(Injector WardenDetector)

# Настройка копирования DLL в папку с инжектором после сборки
add_custom_command(TARGET Injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:WardenDetector>
    $<TARGET_FILE_DIR:Injector>
)

if(BUILD_TESTING)
    add_test(NAME TestAppSmoke COMMAND TestApp --no-wait)

    add_executable(CoreTests
        test/core_tests.cpp
    )
    target_include_directories(CoreTests PRIVATE src)
    add_test(NAME CoreTests COMMAND CoreTests)
endif()
