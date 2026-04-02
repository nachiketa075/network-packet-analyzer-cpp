#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

using namespace std;

ofstream logFile;

int packetCount = 0;
int synPacketCount = 0;

void analyzeTCPPacket(unsigned char* buffer, int packetSize)
{
    struct iphdr *ipHeader = (struct iphdr*)buffer;

    struct sockaddr_in sourceAddress, destinationAddress;

    memset(&sourceAddress, 0, sizeof(sourceAddress));
    sourceAddress.sin_addr.s_addr = ipHeader->saddr;

    memset(&destinationAddress, 0, sizeof(destinationAddress));
    destinationAddress.sin_addr.s_addr = ipHeader->daddr;

    int ipHeaderLength = ipHeader->ihl * 4;

    struct tcphdr *tcpHeader = (struct tcphdr*)(buffer + ipHeaderLength);

    unsigned short sourcePort = ntohs(tcpHeader->source);
    unsigned short destinationPort = ntohs(tcpHeader->dest);

    packetCount++;

    cout << "\n----------------------------------\n";
    cout << "Packet Number      : " << packetCount << endl;
    cout << "Source IP          : " << inet_ntoa(sourceAddress.sin_addr) << endl;
    cout << "Destination IP     : " << inet_ntoa(destinationAddress.sin_addr) << endl;
    cout << "Source Port        : " << sourcePort << endl;
    cout << "Destination Port   : " << destinationPort << endl;
    cout << "Sequence Number    : " << ntohl(tcpHeader->seq) << endl;
    cout << "Ack Number         : " << ntohl(tcpHeader->ack_seq) << endl;

    logFile << "\nPacket Number      : " << packetCount << endl;
    logFile << "Source IP          : " << inet_ntoa(sourceAddress.sin_addr) << endl;
    logFile << "Destination IP     : " << inet_ntoa(destinationAddress.sin_addr) << endl;

    cout << "Flags              : ";

    if (tcpHeader->syn) {
        cout << "SYN ";
        synPacketCount++;
    }

    if (tcpHeader->ack)
        cout << "ACK ";

    if (tcpHeader->fin)
        cout << "FIN ";

    if (tcpHeader->rst)
        cout << "RST ";

    if (tcpHeader->psh)
        cout << "PSH ";

    if (tcpHeader->urg)
        cout << "URG ";

    cout << endl;

    if (destinationPort == 80)
        cout << "Application        : HTTP" << endl;
    else if (destinationPort == 443)
        cout << "Application        : HTTPS" << endl;
    else if (destinationPort == 22)
        cout << "Application        : SSH" << endl;
    else
        cout << "Application        : Other" << endl;

    cout << "Packet Size        : " << packetSize << " bytes" << endl;

    logFile << "Packet Size        : " << packetSize << " bytes" << endl;

    if (synPacketCount > 50)
        cout << "Warning: Possible SYN Flood Attack!" << endl;
}

int main()
{
    int rawSocket;
    unsigned char buffer[65536];

    struct sockaddr socketAddress;
    int socketAddressSize = sizeof(socketAddress);

    logFile.open("packet_log.txt", ios::app);

    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (rawSocket < 0)
    {
        perror("Socket Error");
        return 1;
    }

    cout << "Network Packet Analyzer Started...\n";

    while (true)
    {
        int packetSize = recvfrom(rawSocket, buffer, sizeof(buffer), 0, &socketAddress, (socklen_t*)&socketAddressSize);

        if (packetSize < 0)
        {
            perror("Receive Error");
            return 1;
        }

        struct iphdr *ipHeader = (struct iphdr*)buffer;

        if (ipHeader->protocol == 6)
        {
            analyzeTCPPacket(buffer, packetSize);
        }
    }

    close(rawSocket);
    logFile.close();

    return 0;
}
