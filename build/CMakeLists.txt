cmake_minimum_required(VERSION 3.10.0)

# Set project name
project (ntool)

# Check if the compiler is g++
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "This project requires g++ as the C++ compiler!")
endif()

set(CMAKE_CXX_STANDARD 23)          # Using C++23 standard
set(CMAKE_CXX_STANDARD_REQUIRED ON) # Enforce the standard
set(CMAKE_CXX_EXTENSIONS OFF)       # Disable compiler-specific extensions

# Set paths
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../include)
set(SRC_DIR     ${CMAKE_SOURCE_DIR}/../src)

# Set source files
set(SRCS
    "${SRC_DIR}/traceroute.cpp"
    "${SRC_DIR}/utils.cpp"
    "${SRC_DIR}/icmp.cpp"
    "${SRC_DIR}/ping.cpp"
    "${SRC_DIR}/main.cpp"
)

add_executable(ntool ${SRCS})

# Set compiler flags
set(CXXFLAGS -Wall -Werror -Wextra -g -O2 -fno-rtti -fno-exceptions)
target_compile_options(ntool PRIVATE ${CXXFLAGS})

# Set include directories
include_directories(${INCLUDE_DIR})