#include "network_devices.h"
#include <iostream>
#include <iomanip> // for formatting
#include <chrono> // for capture time
#include "clean_devices.h"
#include <pcap.h>
#include <funcattrs.h>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>
#include <unordered_map>

#ifdef _WIN32
    #include <winsock2.h> // Inclusion for wpcap
    #include <windows.h> // Windows API
    #include <iphlpapi.h> // Windows API for network info
#elif defined(__linux__)
    #include <unistd.h> // UNIX API
#endif


std::mutex trafficMutex;
const int PACKET_THRESHOLD = 50000;  
std::map<std::string, int> trafficData;
std::atomic<bool> running(true);

std::string selectActiveInterface(const std::vector<NetworkDevice>& devices) {

    std::vector<NetworkDevice> activeDevices;
    for (const auto& device : devices) {
        if (device.isUp && device.hasIPAddress) {
            activeDevices.push_back(device);
        }
    }


    if (activeDevices.empty()) {
        std::cout << "No active network devices found!\n";
        return "";
    }


    std::cout << "Available Active Network Interfaces:\n";
    for (size_t i = 0; i < activeDevices.size(); ++i) {
        std::cout << i + 1 << ". " << activeDevices[i].name << " (" << activeDevices[i].description << ")\n";
    }


    int choice = -1;
    while (true) {
        std::cout << "Select a network interface (1-" << activeDevices.size() << "): ";
        std::cin >> choice;

        if (choice >= 1 && choice <= static_cast<int>(activeDevices.size())) {
            break;
        }
        std::cout << "Invalid choice. Try again.\n";
    }

    return activeDevices[choice - 1].name; 
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!running) return;

    std::lock_guard<std::mutex> lock(trafficMutex);
    
    const u_char* ipHeader = packet + 14; // Skip Ethernet header
    char srcIP[16];
    snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15]);
    
    if (srcIP == "192.168.1.45") return;

    trafficData[srcIP]++;
    
    if (trafficData[srcIP] >= PACKET_THRESHOLD) {
        std::cout << "[ALERT] Possible DDoS detected from: " << srcIP << " | Packet count: " << trafficData[srcIP] << "\n";
    }

}


void startDDoSDetection(const std::string& device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "Error opening device " << device << ": " << errbuf << "\n";
        return;
    }

    std::cout << "Monitoring " << device << " for DDoS attacks...\n";

    while (running) {
        pcap_loop(handle, 0, packetHandler, nullptr);
    }

    pcap_close(handle);
}