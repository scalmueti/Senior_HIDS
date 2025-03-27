#include <iostream>
#include <string>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>

void initializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed!" << std::endl;
        exit(1);
    }
}

struct ip_header {
    u_char  ip_vhl;          
    u_char  ip_tos;          
    u_short ip_len;          
    u_short ip_id;           
    u_short ip_off;          
    u_char  ip_ttl;          
    u_char  ip_p;            
    u_short ip_sum;          
    in_addr ip_src, ip_dst;  
};

struct tcp_header {
    u_short th_sport;        
    u_short th_dport;       
    u_int   th_seq;          
    u_int   th_ack;          
    u_char  th_offx2;        
    u_char  th_flags;        
    u_short th_win;          
    u_short th_sum;          
    u_short th_urp;          
};

void sshPacketHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip_header *ip_header = (struct ip_header *)(packet + 14); // IP header starts after Ethernet header
    struct tcp_header *tcp_header = (struct tcp_header *)(packet + 14 + (ip_header->ip_vhl & 0x0F) * 4); // TCP header starts after IP header

    uint16_t srcPort = ntohs(tcp_header->th_sport);
    uint16_t dstPort = ntohs(tcp_header->th_dport);

    // Check for SSH traffic on TCP port 22
    if (srcPort == 22 || dstPort == 22) {
        std::cout << "SSH traffic detected!" << std::endl;
    }
}


void monitorSSHConnection(const std::string& device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // Start capturing packets and pass them to sshPacketHandler
    if (pcap_loop(handle, 0, sshPacketHandler, nullptr) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
    }

    pcap_close(handle);
}

