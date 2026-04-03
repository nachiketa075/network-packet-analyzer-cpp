Network Packet Analyzer (C++)
A C++ based network packet analyzer built on Kali Linux using raw sockets to capture and analyze live TCP packets.
Features

Captures live TCP packets directly from network layer
Extracts source IP, destination IP, source port, and destination port
Parses TCP sequence number and acknowledgment number
Detects TCP control flags such as SYN, ACK, FIN, RST
Identifies basic protocols such as HTTP, HTTPS, and SSH
Logs packet details into a file automatically
Detects possible SYN flood behavior through repeated SYN packets

Technologies Used

C++
Raw Socket Programming
TCP/IP
Linux Networking
File Handling
Operating Systems Concepts

Sample Output
Packet Number: 1
Source IP: 192.168.1.5
Destination IP: 142.250.x.x
Source Port: 54321
Destination Port: 443
Flags: SYN ACK
