cmake_minimum_required(VERSION 3.12)
project(Tutorial-LiveTraffic)

# Set C++11 standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Paths to PcapPlusPlus include and library directories
set(PcapPlusPlus_INCLUDE_DIR "/root/projects/resaa-transparent-node/pcapplusplus-24.09-ubuntu-22.04-gcc-11.4.0-x86_64/include")
set(PcapPlusPlus_LIB_DIR "/root/projects/resaa-transparent-node/pcapplusplus-24.09-ubuntu-22.04-gcc-11.4.0-x86_64/lib")

# Add include and library directories
include_directories(${PcapPlusPlus_INCLUDE_DIR})
link_directories(${PcapPlusPlus_LIB_DIR})

# Define the executable
add_executable(${PROJECT_NAME} main.cpp)

# Link the PcapPlusPlus library
target_link_libraries(${PROJECT_NAME} PRIVATE PcapPlusPlus)

# Set the output directory for the executable
set_target_properties(${PROJECT_NAME} PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")