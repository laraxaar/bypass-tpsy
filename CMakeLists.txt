cmake_minimum_required(VERSION 3.20)
project(bypass_tpsy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Global Windows defines
add_compile_definitions(
    _WIN32_WINNT=0x0601 
    WIN32_LEAN_AND_MEAN
)

# Use local libs directory
set(LIBS_DIR "${CMAKE_SOURCE_DIR}/libs")

# Header includes
include_directories(
    include
    ${LIBS_DIR}
)

# Binary link directories
link_directories(
    ${LIBS_DIR}
)

# Source files mapping
set(SOURCES
    src/main.cpp
    src/logger.cpp
    src/config.cpp
    src/packet.cpp
    src/tls_parser.cpp
    src/quic_parser.cpp
    src/dns_proxy.cpp
    src/tunnel_io.cpp
    src/inject_io.cpp
    src/route_table.cpp
    src/route_refresher.cpp
    src/seq_tracker.cpp
    src/bypass_strategy.cpp
    src/stats.cpp
    src/resource_extractor.cpp
)

add_executable(bypass_tpsy ${SOURCES} resources.rc)

# System Windows libraries
target_link_libraries(bypass_tpsy ws2_32 iphlpapi winhttp ntdll WinDivert)

if(MSVC)
    # /W4 - высокий уровень предупреждений, /EHsc - стандартные исключения
    target_compile_options(bypass_tpsy PRIVATE /W4 /EHsc)
    
    # 1. ОБЪЯВЛЯЕМ NTSTATUS НАПРЯМУЮ: Говорим компилятору во всех файлах, что NTSTATUS это long.
    # Это мгновенно чинит ошибки отсутствия типа в netioapi.h / iphlpapi.h
    target_compile_definitions(bypass_tpsy PRIVATE "NTSTATUS=long")
    
    # 2. ПРИНУДИТЕЛЬНЫЕ ИНКЛУДЫ: Вшиваем только чистый базовый сетевой стек Windows.
    # Убираем отсюда "ntstatus.h", чтобы полностью стереть спам из сотен варнингов C4005!
    target_compile_options(bypass_tpsy PRIVATE /FI"winsock2.h" /FI"ws2tcpip.h" /FI"windows.h")
endif()