cmake_minimum_required(VERSION 3.10)
project(transparent-node)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the PcapPlusPlus package
find_package(PcapPlusPlus REQUIRED)

# Add the executable with all source files
add_executable(transparent-node
    src/ip-redirector.cpp  # Added this file to the compilation
    # src/wire.cpp
)

# Link the PcapPlusPlus libraries to your executable
target_link_libraries(transparent-node
    PUBLIC
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Common++
    ${PCAP_LIBRARY}  # Ensure libpcap is linked
    pthread           # With the PUBLIC keyword
)


# Ensure that PcapPlusPlus include directories are included
target_include_directories(transparent-node PRIVATE ${PcapPlusPlus_INCLUDE_DIRS})

# Optionally, if PcapPlusPlus requires certain libraries (for example, pthread), make sure they are linked
target_link_libraries(transparent-node PRIVATE pthread)
