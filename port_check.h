#ifndef PORT_CHECK_H
#define PORT_CHECK_H

#include <iostream>
#include <string>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>

void sshPacketHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void monitorSSHConnection(const std::string& device);

#endif
