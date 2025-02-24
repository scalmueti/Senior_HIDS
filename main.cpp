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

std::string detectOS() {
    std::string status;
    #ifdef _WIN32
        std::cout << "Running on Windows, using Npcap.\n";
        status = "WINDOWS";
        return status;
    #elif __APPLE__
        std::cout << "Running on macOS, using libpcap.\n";
        status = "MACOS";
        return status;
    #elif __linux__
        std::cout << "Running on Linux, using libpcap.\n";
        status = "LINUX";
        return status;
    #else
        std::cout << "Unknown OS, packet capture might not work!\n";
        status = "WINDOWS";
        return status;
    #endif
}

int main() {
    std::string usedOS = detectOS(); 
    menu();
}