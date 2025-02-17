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

