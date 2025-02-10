#include "network_devices.h"
#include <iostream>
#include <iomanip> // for formatting
#include <chrono> // for capture time
#include "clean_devices.h"
#include <pcap.h>
#include <funcattrs.h>

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
#elif defined(__linux__)
    #include <unistd.h> // UNIX API
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

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        NetworkDevice device;
        device.name = d->name;
        device.description = (d->description) ? d->description : "No description available";
        device.packetCount = 0;
        devices.push_back(device);
    }
    pcap_freealldevs(alldevs);
    return devices;
}

void captureTraffic(NetworkDevice& device) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(device.name.c_str(), 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening device " << device.name << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "Capturing packets on " << device.name << " (" << device.description << ")" << std::endl;

    struct pcap_pkthdr header;
    const u_char *packet;
    for (int i = 0; i < 10; ++i) {
        packet = pcap_next(handle, &header);
        std::cout << "Captured a packet of length: " << header.len << std::endl;   
        device.packetCount++;
    }

    pcap_close(handle);
}

NetworkDevice detectMainDevice(const std::vector<NetworkDevice>& devices) {
    NetworkDevice mainDevice;
    int maxPackets = -1;

    for (const auto& device : devices) {
        if (device.packetCount > maxPackets) {
            maxPackets = device.packetCount;
            mainDevice = device;
        }
    }
    return mainDevice;
}