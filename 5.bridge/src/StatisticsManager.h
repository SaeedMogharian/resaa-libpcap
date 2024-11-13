#ifndef STATISTICSMANAGER_H
#define STATISTICSMANAGER_H

#include <unordered_map>
#include <string>
#include <iostream>
#include <iomanip>
#include "IpStats.h"

class StatisticsManager {
private:
    std::unordered_map<std::string, IpStats> ip_statistics;

public:
    void update(const u_char* packet, int packet_size, const std::string& interface, int link_header_length);
    void print() const;
};

#endif // STATISTICSMANAGER_H
