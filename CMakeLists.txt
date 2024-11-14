cmake_minimum_required(VERSION 3.29)
project(resaa_libpcap)

# Set the C++ standard to 14
set(CMAKE_CXX_STANDARD 14)

# Include directories
include_directories(.)

# Specify the source files
set(SOURCES
        6.rel/rel.cpp
        4.sniffinject/sniffinject.cpp
)

# Add the executable target
add_executable(${PROJECT_NAME} ${SOURCES})

# Link the pcap library
target_link_libraries(${PROJECT_NAME} pcap)
