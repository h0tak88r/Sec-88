# Networking Fundamentals

## Network Security Notes

### Basic Definitions Related to Networking

1. **Network**: A collection of **interconnected devices** (e.g., computers, servers) for **communication** and **resource sharing**.
2. **Protocol**: Rules and standards governing communication in a network.
3. **IP Address**: Unique numerical identifier for devices on a network.
4. **Router**: Device forwarding data between different networks, directing traffic.
5. **Switch**: Connects devices on a local network, forwarding data based on MAC addresses.
6. **Firewall**: Monitors and controls network traffic, enforcing access policies.
7. **DNS** (Domain Name System): Translates domain names to IP addresses.
8. **DHCP**: Assigns IP addresses and network configuration automatically.
9. **LAN** (Local Area Network): Connects devices in a limited area.
10. **WAN** (Wide Area Network): Spans large distances, connecting LANs.
11. **Ethernet**: Standard for wired connections, defining OSI model layers.
12. **Wi-Fi**: Wireless networking allowing cable-free connections.
13. **VPN** (Virtual Private Network): Secure connection over a public network.
14. **Bandwidth**: Maximum data transmitted over a network in a given time.
15. **Latency**: Time delay in data transmission over a network.
16. **Clients**: Devices requesting services/resources from servers.
17. **Server**: Stores and manages resources, responding to client requests.
18. **Request-Response**: Client-server interaction: request, process, respond.
19. **Resource Sharing**: Servers share resources with multiple clients.
20. **Scalability**: Capability for multiple clients to connect to a server.
21. **Client Responsibility**: Clients handle services/resources received.

### Most Common Protocols

| Protocol | Port Number | Description                           |
| -------- | ----------- | ------------------------------------- |
| HTTP     | 80          | Hypertext Transfer Protocol           |
| HTTPS    | 443         | HTTP Secure                           |
| FTP      | 21          | File Transfer Protocol                |
| SSH      | 22          | Secure Shell                          |
| Telnet   | 23          | Telnet Protocol                       |
| SMTP     | 25          | Simple Mail Transfer Protocol         |
| DNS      | 53          | Domain Name System                    |
| DHCP     | 67/68       | Dynamic Host Configuration Protocol   |
| POP3     | 110         | Post Office Protocol 3                |
| IMAP     | 143         | Internet Message Access Protocol      |
| RDP      | 3389        | Remote Desktop Protocol               |
| NTP      | 123         | Network Time Protocol                 |
| SNMP     | 161         | Simple Network Management Protocol    |
| LDAP     | 389         | Lightweight Directory Access Protocol |
| SMTPS    | 465         | SMTP Secure                           |
| SIP      | 5060/5061   | Session Initiation Protocol           |
| FTPS     | 990         | FTP Secure                            |

### Network Types

* **Local Area Network (LAN)**: Connects devices in a limited geographical area.
* **Wide Area Network (WAN)**: Spans large distances, connecting multiple LANs.
* **Metropolitan Area Network (MAN)**: Covers a larger geographic area than a LAN.
* **Campus Area Network (CAN)**: Interconnects LANs within a university campus or large organization.
* **Personal Area Network (PAN)**: Connects devices in close proximity to an individual.
* **Wireless Local Area Network (WLAN)**: LAN using wireless communication technologies.
* **Virtual Private Network (VPN)**: Provides a secure, encrypted connection over a public network.
* **Storage Area Network (SAN)**: Dedicated network providing high-speed access to shared storage devices.
* **Cloud Computing Network**: Infrastructure used in cloud computing environments.
* **Internet**: Global network of interconnected networks.

### 7 Layer OSI Model

| Layer | Name         | Function                                                              | Typical Use                      | Protocols                            |
| ----- | ------------ | --------------------------------------------------------------------- | -------------------------------- | ------------------------------------ |
| 7     | Application  | Interface between software applications and the network               | End User Layer                   | HTTP, FTP, SSH, DNS                  |
| 6     | Presentation | Translates data into a format understood by the application layer     | Syntax Layer                     | SSL, SSH, IMAP, MPEG, JPEG           |
| 5     | Session      | Establishes, manages, and terminates connections between applications | Sync & Send Layer, APIs, Sockets |                                      |
| 4     | Transport    | Ensures reliable delivery of data between hosts                       | End-to-end Connections           | TCP, UDP                             |
| 3     | Network      | Handles routing of data packets between networks                      | Packets                          | IP, ICMP, IPSec, IGMP                |
| 2     | Data Link    | Manages data transmission over a physical link                        | Frames                           | Ethernet, PPP, Switch                |
| 1     | Physical     | Transmits raw data bits over a physical medium                        | Physical Structure               | Fiber, Access Points, Copper Cabling |

### Network Topologies

* **Bus Topology**: All computers connected to a single cable.
* **Star Topology**: Each node connected to a switch.
* **Ring Topology**: Each node connected to one other, reducing packet collision.
* **Mesh Topology**: Each node has an independent connection to every other node.

### Network Cables - Copper

| Cable Type | Max Data Transfer Speed | Max Operating Length |
| ---------- | ----------------------- | -------------------- |
| CAT5       | 100 Mbps                | 100 Meters           |
| CAT5e      | 1 Gbps                  | 100 Meters           |
| CAT6       | 10 Gbps                 | 55 Meters            |
| CAT6a      | 10 Gbps                 | 100 Meters           |
| CAT7       | 10 Gbps                 | 100 Meters           |
| CAT8       | 40 Gbps                 | 30 Meters            |

### Network Cables - Fiber

| Cable Type          | Max Speed/Distance    | Typical Use                                                                              |
| ------------------- | --------------------- | ---------------------------------------------------------------------------------------- |
| OM1 - Orange Jacket | 10 Gbps/33 Meters     | 100 Mbps Ethernet                                                                        |
| OM2 - Orange Jacket | 10 Gbps/82 Meters     | 1 Gbps Ethernet                                                                          |
| OM3 - Aqua Jacket   | 10 Gbps/300 Meters    | 10 Gbps Ethernet                                                                         |
| OM4 - Aqua Jacket   | 10 Gbps/400 Meters    | 100 Gbps Ethernet @ 150 meters                                                           |
| OM5 - Green Jacket  | 10 Gbps/400 Meters    | Improvements on OM4. Efficient light wavelength breakdown.                               |
| OS1 - Yellow Jacket | Up to 100 Gbps/10 km  | Single-mode fiber for indoor nodes. Used in fiber internet connections and data centers. |
| OS2 - Yellow Jacket | Up to 100 Gbps/200 km | Single-mode fiber for outdoor infrastructure. Used for MANs, ISPs, or MSPs.              |

### OSI Troubleshooting&#x20;

| Layer        | Command                      | Purpose                                                                          |
| ------------ | ---------------------------- | -------------------------------------------------------------------------------- |
| Physical     | `ip -br -c link`             | Check physical interface status. Detailed NIC and virtual NIC information.       |
| Data Link    | `ip neighbor show`           | Display ARP table showing IP and MAC addresses of reachable devices.             |
| Network      | `ip -br -c address show`     | Check NIC connection status, IP address, and CIDR. Ensure valid IP on LAN NIC.   |
|              | `ping <website or IP>`       | Ping device for connectivity or use a common server like Google's DNS (8.8.8.8). |
|              | `traceroute <website or IP>` | Show routers packet interacted with. Use for troubleshooting.                    |
|              | `nslookup <website name>`    | Check DNS entries on your server. Ensure IPs match ping results.                 |
| Transport    | `ss -tunlp4`                 | Show socket statistics. Verify connections and ports on the server.              |
| Session      | `ssh` or `rtp`               | Establish SSH session or initiate RTP session for testing.                       |
| Presentation | `html`, `rtsp`               | Connect to a camera's webpage or query a camera stream through VLC.              |
| Application  | Using the program            | Interact with a webpage or view DS logs to confirm the application is running.   |

### Network Hardware

* **Network Interface Controller (NIC)**: Ethernet jack on a computer.
* **Wireless Network Interface Controller**: Uses radio waves to connect to an access point.
