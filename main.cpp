#include <iostream>
#include <iomanip>
#include "network_devices.h"
#include "clean_devices.h"

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

int main() {
    detectOS(); 

    auto devices = getNetworkDevices();

    if (devices.empty()) {
        std::cout << "No network devices found!" << std::endl;
        return 1;
    }

    std::cout << "Detected " << devices.size() << " network devices." << std::endl;

    for (auto& device : devices) {
        std::cout << "Capturing traffic on: " << device.name << " (" << device.description << ")" << std::endl;
        captureTraffic(device);
    }

    NetworkDevice mainDevice = detectMainDevice(devices);
    
    std::cout << "Main interface: " << mainDevice.name << " (" << mainDevice.description << ")" << std::endl;
    return 0;
}