#ifndef DDOS_H
#define DDOS_H

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
#include <atomic>
#include <map>

// Function Prototypes
std::string selectActiveInterface(const std::vector<NetworkDevice>& devices);
void startDDoSDetection(const std::string& device);
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif