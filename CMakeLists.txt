cmake_minimum_required(VERSION 3.10)
project(transparent-node)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the PcapPlusPlus package
find_package(PcapPlusPlus REQUIRED)

# Add the executable
add_executable(transparent-node src/wire.cpp)

# Link the PcapPlusPlus libraries to your executable
target_link_libraries(transparent-node
    Packet++
    Pcap++
    Common++
    ${PCAP_LIBRARY}  # Ensure libpcap is linked
)
