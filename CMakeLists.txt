cmake_minimum_required(VERSION 3.10)
project(BypassTpsy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/proxy_server.cpp
    src/bypass_engine.cpp
    src/wfp_manager.cpp
    src/wintun_manager.cpp
    src/dns_resolver.cpp
    src/ui_manager.cpp
)

# Header files (for IDE visibility)
set(HEADERS
    include/network_util.h
    include/wintun_helper.h
    include/wfp_manager.h
)

add_executable(bypass_tpsy ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(bypass_tpsy ws2_32 fwpuclnt iphlpapi)

# MSVC specific flags
if(MSVC)
    target_compile_options(bypass_tpsy PRIVATE /W4 /EHsc)
endif()
