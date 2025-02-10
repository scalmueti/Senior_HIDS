#include "network_devices.h"
#include <iostream>
#include <iomanip> // for formatting
#include "clean_devices.h"

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

#ifdef _WIN32
    #include <winsock2.h> // Inclusion for wpcap
    #include <windows.h> // Windows API
    #include <pcap.h> // Npcap
    #include <funcattrs.h> // libpcap dependency
#elif defined(__linux__)
    #include <unistd.h> // UNIX API
    #include <pcap.h> // libpcap
    #include <funcattrs.h> // libpcap dependency
#endif

std::vector<NetworkDevice> getNetworkDevices() {
    //Init pcap
    std::vector<NetworkDevice> devices;
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return devices;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        NetworkDevice device;
        device.name = cleanDeviceName(dev->name);
        device.description = (dev->description) ? dev->description : "No description available"; 
        devices.push_back(device);
    }

    pcap_freealldevs(alldevs);
    return devices;
}