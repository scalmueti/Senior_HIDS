#ifndef NETWORK_DEVICES_H
#define NETWORK_DEVICES_H

#include <vector>
#include <string>
#include <pcap.h>
#include <iostream>
#include <iomanip> // for formatting
#include <chrono> // for capture time

// defines struct for storing network device details
struct NetworkDevice {
    std::string name;
    std::string description;
    int packetCount;
};

// func
void displayNetworkDevices(const std::vector<NetworkDevice>& devices);
std::vector<NetworkDevice> getNetworkDevices();
NetworkDevice detectMainDevice(const std::vector<NetworkDevice>& devices);
void captureTraffic(NetworkDevice& device);

#endif
