cmake_minimum_required(VERSION 3.16)
project(oMac-vsomeip VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

# OpenSSL — required for AES-128-CMAC
find_package(OpenSSL REQUIRED)

# nlohmann/json — downloaded automatically at configure time
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    DOWNLOAD_NO_EXTRACT TRUE          # it's a single header, not an archive
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/nlohmann
)
FetchContent_MakeAvailable(nlohmann_json)
set(NLOHMANN_JSON_INCLUDE ${CMAKE_BINARY_DIR})

# ---------------------------------------------------------------------------
# omac — core static library (no vsomeip dependency)
#
# Includes:
#   - footer helpers (header-only, transitively pulled in by the library)
#   - crypto (OpenSSL AES-128-CMAC)
#   - automaton (string-based state machine + JSON policy loading)
#   - reference_monitor (crypto + automaton wired together)
# ---------------------------------------------------------------------------
add_library(omac STATIC
    src/crypto.cpp
    src/automaton.cpp
    src/reference_monitor.cpp
)

target_include_directories(omac PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${NLOHMANN_JSON_INCLUDE}           # points to build/nlohmann/ after FetchContent
)

target_link_libraries(omac PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# ---------------------------------------------------------------------------
# Tests — always built, do NOT require vsomeip
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)

# ---------------------------------------------------------------------------
# Examples — require vsomeip; disable with -DBUILD_EXAMPLES=OFF
# ---------------------------------------------------------------------------
option(BUILD_EXAMPLES "Build vsomeip example applications" ON)

if(BUILD_EXAMPLES)
    # Try to find vsomeip3; skip examples gracefully if not installed
    find_package(vsomeip3 QUIET)
    if(vsomeip3_FOUND)
        add_subdirectory(examples)
    else()
        message(WARNING
            "vsomeip3 not found — skipping examples. "
            "Install vsomeip or set vsomeip3_DIR to enable them.")
    endif()
endif()
