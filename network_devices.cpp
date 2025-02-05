#include "network_devices.h"
#include <iostream>
#include <iomanip> // for formatting

void displayNetworkDevices(const std::vector<NetworkDevice>& devices) {
    std::cout << "\nAvailable Network Interfaces:\n";
    std::cout << std::left << std::setw(5) << "No." 
              << std::setw(40) << "Interface Name" 
              << "Description\n";
    std::cout << std::string(80, '-') << "\n"; // Separator line

    for (size_t i = 0; i < devices.size(); ++i) {
        std::cout << std::left << std::setw(5) << (i + 1)
                  << std::setw(40) << devices[i].name
                  << devices[i].description << "\n";
    }
}
