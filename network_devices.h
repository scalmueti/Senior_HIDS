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
    bool isUp;
    bool hasIPAddress;
};

// func
void displayNetworkDevices(const std::vector<NetworkDevice>& devices);
std::vector<NetworkDevice> getNetworkDevices();
void scanDevicesStatus(const std::vector<NetworkDevice>& devices);

/*
NetworkDevice detectMainDevice(const std::vector<NetworkDevice>& devices);
int captureTraffic(pcap_t *handle, int durationMs);
std::vector<NetworkDevice> detectActiveInterfaces(const std::vector<NetworkDevice>& devices);
*/

#endif
