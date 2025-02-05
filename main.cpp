#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <iomanip>
#include "network_devices.h"

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

void detectOS() {
    #ifdef _WIN32
        std::cout << "Running on Windows, using Npcap.\n";
    #elif __APPLE__
        std::cout << "Running on macOS, using libpcap.\n";
    #elif __linux__
        std::cout << "Running on Linux, using libpcap.\n";
    #else
        std::cout << "Unknown OS, packet capture might not work!\n";
    #endif
}

std::string cleanDeviceName(const std::string &rawName) {
    std::regex npfPattern(R"(\\Device\\NPF_\{([0-9A-Fa-f\-]+)\})");
    std::smatch match;

    if (std::regex_match(rawName, match, npfPattern) && match.size() > 1) {
        return match[1];
    }
    return rawName;
}

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

int main() {
    detectOS(); 

    std::vector<NetworkDevice> devices = getNetworkDevices();

    if (devices.empty()) {
        std::cout << "No network devices found.\n";
        return 1;
    }

    displayNetworkDevices(devices);

    std::cout << "\nPress enter to exit...";
    std::cin.get();

    return 0;
}