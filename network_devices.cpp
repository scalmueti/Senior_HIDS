#include "network_devices.h"
#include <iostream>
#include <iomanip> // for formatting
#include <chrono> // for capture time
#include "clean_devices.h"
#include <pcap.h>
#include <funcattrs.h>
#include <thread>
#include <mutex>
#include <unordered_map>
#include "ddos.h"
#include "port_check.h"

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
    #include <iphlpapi.h> // Windows API for network info
#elif defined(__linux__)
    #include <unistd.h> // UNIX API
#endif

bool hasIPAddress(const std::string& deviceName) {
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &outBufLen);
    std::vector<unsigned char> buffer(outBufLen);
    IP_ADAPTER_ADDRESSES *pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) != NO_ERROR) {
        return false;
    }

    std::string deviceGUID = cleanDeviceName(deviceName);  // Extract GUID from device name

    for (IP_ADAPTER_ADDRESSES *adapter = pAddresses; adapter; adapter = adapter->Next) {
        std::string adapterGUID = adapter->AdapterName;

        // Remove braces from AdapterName if they exist
        adapterGUID.erase(std::remove(adapterGUID.begin(), adapterGUID.end(), '{'), adapterGUID.end());
        adapterGUID.erase(std::remove(adapterGUID.begin(), adapterGUID.end(), '}'), adapterGUID.end());

        if (adapter->OperStatus == IfOperStatusUp && adapterGUID == deviceGUID) {
            return adapter->FirstUnicastAddress != nullptr;  // True if the adapter has an IP
        }
    }
    return false;
}

std::vector<NetworkDevice> getNetworkDevices() {
    std::vector<NetworkDevice> devices;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return devices;
    }

    for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next) {
        NetworkDevice networkDevice;
        networkDevice.name = dev->name;
        networkDevice.description = dev->description ? dev->description : "No description";

        pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        networkDevice.isUp = handle != nullptr;
        if (handle) pcap_close(handle);

        networkDevice.hasIPAddress = hasIPAddress(networkDevice.name);

        if (networkDevice.isUp && networkDevice.hasIPAddress) {
            devices.push_back(networkDevice);
        }
    }

    pcap_freealldevs(alldevs);
    return devices;
    
}

void scanDevicesStatus(const std::vector<NetworkDevice>& devices) {
    for (const auto& device : devices) {
        std::cout << "Device: " << device.description << " (GUID: " << device.name << ")\n";
        std::cout << "Status: " << (device.isUp ? "Up" : "Down") << "\n";
    }
}

void menu() {

    std::mutex trafficMutex;
    const int PACKET_THRESHOLD = 1000;  
    std::map<std::string, int> trafficData;
    std::atomic<bool> running(true);

    while (true) {
        std::cout << "\n=== Network Security Tool ===\n";
        std::cout << "1. Scan Active Network Interfaces\n";
        std::cout << "2. Start DDoS Detection\n";
        std::cout << "3. Start SSH Login Detection\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter choice: ";

        int choice;
        std::cin >> choice;

        if (choice == 1) {
            auto devices = getNetworkDevices();

            if (devices.empty()) {
                std::cout << "No network devices found!" << std::endl;
            }

            std::cout << "Detected " << devices.size() << " network devices." << std::endl;

            scanDevicesStatus(devices);
        } else if (choice == 2) {
            auto devices = getNetworkDevices();
            std::string selectedDevice = selectActiveInterface(devices);
            if (!selectedDevice.empty()) {
                running = true;
                std::thread ddosThread(startDDoSDetection, selectedDevice);
                
                std::cout << "Press Enter to stop DDoS monitoring...\n";
                std::cin.ignore();
                std::cin.get();
                
                running = false;
                ddosThread.join();
            }
        } else if (choice == 3) {
            auto devices = getNetworkDevices();
            std::string selectedDevice = selectActiveInterface(devices);
            if (!selectedDevice.empty()) {
                running = true;
                std::thread SSHthread(monitorSSHConnection, selectedDevice);

                std::cout << "Press Enter to stop SSH monitoring...\n";
                std::cin.ignore();
                std::cin.get();

                running = false;
                SSHthread.join();
            }
        } else if (choice == 4) {
            std::cout << "Exiting...\n";
            break;
        } else {
            std::cout << "Invalid choice. Try again.\n";
        
        }
    }
}