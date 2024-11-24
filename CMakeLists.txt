# Minimum version requirement
cmake_minimum_required(VERSION 3.10)

# Project name
project(ipPass)

# Define the package directory (replace with your path)
set(PACKAGE_DIR "/root/projects/resaa-transparent-node/pcapplusplus-24.09-ubuntu-22.04-gcc-11.4.0-x86_64")

# Set the PKG_CONFIG_PATH to find the PcapPlusPlus library
set(ENV{PKG_CONFIG_PATH} "${PACKAGE_DIR}/lib/pkgconfig")

# Use pkg-config to find PcapPlusPlus
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAPPLUSPLUS REQUIRED PcapPlusPlus)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the target executable and source file
add_executable(ipPass ipPass.cpp)

# Include directories from pkg-config
target_include_directories(ipPass PRIVATE ${PCAPPLUSPLUS_INCLUDE_DIRS})

# Link libraries from pkg-config
target_link_libraries(ipPass PRIVATE ${PCAPPLUSPLUS_LIBRARIES})

# Add compile options from pkg-config
target_compile_options(ipPass PRIVATE ${PCAPPLUSPLUS_CFLAGS_OTHER})

# Add linker options from pkg-config
target_link_options(ipPass PRIVATE ${PCAPPLUSPLUS_LDFLAGS_OTHER})

# Add a custom target for cleaning
# add_custom_target(clean
#     COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/ipPass ${CMAKE_BINARY_DIR}/*.o
#     COMMENT "Cleaning up generated files"
# )
