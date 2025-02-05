#ifndef NETWORK_DEVICES_H
#define NETWORK_DEVICES_H

#include <vector>
#include <string>

// defines struct for storing network device details
struct NetworkDevice {
    std::string name;
    std::string description;
};

// func
void displayNetworkDevices(const std::vector<NetworkDevice>& devices);

#endif
