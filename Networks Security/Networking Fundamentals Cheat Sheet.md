- **Basic definitions related to networking**
    
    1. ==**Network**==: A collection of **interconnected devices**, such as **computers** or **servers**, that can **communicate** and **share resources**.
    2. ==**Protocol**==: A set of rules and standards that governs communication between devices in a network.
    3. ==**IP Address**==: A unique numerical identifier assigned to each device on a network, allowing for proper addressing and routing of data packets.
    4. ==**Router**==: A network device that forwards data packets between different networks, directing traffic to its intended destination.
    5. ==**Switch**==: A network device that connects multiple devices on a local network, forwarding data packets to the appropriate recipient based on their MAC addresses.
    6. ==**Firewall**==: A security device or software that monitors and controls incoming and outgoing network traffic, enforcing access policies and protecting against unauthorized access.
    7. ==**DNS**== (Domain Name System): A system that translates domain names (e.g., [**www.example.com**](http://www.example.com/)) into IP addresses, enabling users to access websites by name instead of IP addresses.
    8. ==**DHCP**== (Dynamic Host Configuration Protocol): A network protocol that automatically assigns IP addresses and other network configuration parameters to devices on a network.
    9. ==**LAN**== (Local Area Network): A network that connects devices within a limited geographic area, such as a home, office, or campus.
    10. ==**WAN**== (Wide Area Network): A network that spans large distances, connecting multiple LANs or other networks together.
    11. ==**Ethernet**==: A widely used standard for wired network connections, defining the physical and data link layers of the OSI model.
    12. ==**Wi-Fi**==: A wireless networking technology that allows devices to connect to a network without the need for physical cables.
    13. ==**VPN**== (Virtual Private Network): A secure and private network connection established over a public network, such as the internet, enabling secure remote access or data transmission.
    14. ==**Bandwidth**==: The maximum amount of data that can be transmitted over a network connection within a given time, usually measured in bits per second (bps) or its multiples.
    15. ==**Latency**==: The time delay experienced in data transmission over a network, often caused by factors such as distance, congestion, or processing time
    16. ==**Clients**==: Clients are devices, such as computers, smartphones, or tablets, that request services or resources from the server. Clients initiate communication by sending requests to the server.
    17. ==**Server**==: The server is a powerful computer or network of computers that store and manage resources or services. It waits for incoming requests from clients and responds to those requests by providing the requested services or resources.
    18. ==**Request-Response**==: The client sends a request to the server, specifying the desired service or resource. The server receives the request, processes it, and sends a response back to the client, fulfilling the request.
    19. ==**Resource Sharing**==: The server manages and shares its resources with multiple clients. These resources can include files, databases, processing power, network services, or any other service that the server is capable of providing.
    20. ==**Scalability**==: The client-server model allows for scalability, as multiple clients can connect to the server simultaneously. The server can handle and respond to requests from multiple clients efficiently, enabling a large number of users to access its services concurrently.
    21. ==**Client Responsibility**==: Clients are typically responsible for displaying or utilizing the services or resources received from the server. They may handle user interfaces, data processing, and rendering of information received from the server
    
- **Most common Protocols**
    
    |   |   |   |
    |---|---|---|
    |Protocol|Port Number|Description|
    |HTTP|80|Hypertext Transfer Protocol|
    |HTTPS|443|HTTP Secure|
    |FTP|21|File Transfer Protocol|
    |SSH|22|Secure Shell|
    |Telnet|23|Telnet Protocol|
    |SMTP|25|Simple Mail Transfer Protocol|
    |DNS|53|Domain Name System|
    |DHCP|67/68|Dynamic Host Configuration Protocol|
    |POP3|110|Post Office Protocol 3|
    |IMAP|143|Internet Message Access Protocol|
    |RDP|3389|Remote Desktop Protocol|
    |NTP|123|Network Time Protocol|
    |SNMP|161|Simple Network Management Protocol|
    |LDAP|389|Lightweight Directory Access Protocol|
    |SMTPS|465|SMTP Secure|
    |SIP|5060/5061|Session Initiation Protocol|
    |FTPS|990|FTP Secure|
    

### Network Types

|   |   |
|---|---|
|**Network Type**|**Description**|
|Local Area Network (**LAN**)|A network that connects devices within a limited geographical area, such as a home, office, or school campus.|
|Wide Area Network (**WAN**)|A network that spans large distances and connects multiple LANs or other networks together, often using public infrastructure like the Internet.|
|Metropolitan Area Network (**MAN**)|A network that covers a larger geographic area than a LAN, typically spanning a city or metropolitan region.|
|Campus Area Network (**CAN**)|A network that interconnects multiple LANs within a university campus or large organization.|
|Personal Area Network (**PAN**)|A network that connects devices in close proximity to an individual, such as Bluetooth devices or wearable technology.|
|Wireless Local Area Network (**WLAN**)|A LAN that uses wireless communication technologies, allowing devices to connect without physical cables.|
|Virtual Private Network (**VPN**)|A network that provides a secure, encrypted connection over a public network, enabling remote access or secure data transmission.|
|Storage Area Network (**SAN**)|A dedicated network that provides high-speed access to shared storage devices, typically used in enterprise storage systems.|
|Cloud Computing Network|A network infrastructure used in cloud computing environments to enable access to services and resources over the internet.|
|Internet|The global network of interconnected networks, allowing devices and users worldwide to communicate and access information.|

### 7 Layer OSI Model

|   |   |   |   |   |
|---|---|---|---|---|
|Layer|Name|Function|Typical Use|Protocols|
|7|Application|Provides interface between software applications and the network.|End User Layer|HTTP, FTP, SSH, DNS|
|6|Presentation|Translates data into a format that can be understood by the application layer. Encrypts and decrypts data.|Syntax Layer|SSL, SSH, IMAP, MPEG, JPEG|
|5|Session|Establishes, manages, and terminates connections between applications.|Sync & Send Layer, APIs, Sockets||
|4|Transport|Ensures reliable delivery of data between hosts. Handles segmentation and reassembly of data.|End-to-end Connections|TCP, UDP|
|3|Network|Handles routing of data packets between networks, using logical addressing.|Packets|IP, ICMP, IPSec, IGMP|
|2|Data Link|Manages data transmission over a physical link. Handles error detection and correction.|Frames|Ethernet, PPP, Switch|
|1|Physical|Transmits raw data bits over a physical medium.|Physical Structure|Fiber, Access Points, Copper Cabling|

### Network Topologies

|   |   |   |
|---|---|---|
|**Bus Topology**|All computers are connected to a single cable|Antiquated process - still used in broadcast media|
|**Star Topology**|Each node is connected to a switch|Most common network setup you will see|
|**Ring Topology**|Each node is connected to one other. Reduces chances of packet collision|Rarely seen outside of a MAN or ISP datace­nte­r-t­o-d­ata­center connection|
|**Mesh Topology**|Each node has an indepe­ndent connection to every other node on the network|Used by MSPs and ISPs for highly­-av­ailable and fault tolerant networks.|

### Network Cables - Copper

|   |   |   |
|---|---|---|
|**Cable Type**|**Max data transfer speed**|**Max Operating Length**|
|**CAT5**|100 Mbps|100 Meters|
|**CAT5e**|1 Gbps|100 Meters|
|**CAT6**|10 Gbps|55 Meters|
|**CAT6a**|10 Gbps|100 Meters|
|**CAT7**|10 Gbps|100 Meters|
|**CAT8**|40 Gbps|30 Meters|

### Network Cables - Fiber

|   |   |   |
|---|---|---|
|**Cable Type**|**Max Speed/­Dis­tance**|**Typical Use**|
|**OM1** - Orange Jacket|10 Gbps/33 Meters|100 Mbps Ethernet|
|**OM2** - Orange Jacket|10 Gbps/82 Meters|1 Gbps Ethernet|
|**OM3** - Aqua Jacket|10 Gbps/300 Meters|10 Gbps Ethernet|
|**OM4** - Aqua Jacket|10 Gbps/400 Meters|100 Gbps Ethernet @ 150 meters|
|**OM5** - Green Jacket|10 Gbps/400 Meters|Improv­ements on OM4. It breaks down light wavele­ngths more effici­ently.|
|**OS1** - Yellow Jacket|up to 100 Gbps/10 km|Single mode fiber for connecting indoor nodes. Used in fiber internet connec­tions and datace­nters.|
|**OS2** - Yellow Jacket|up to 100 Gbps/200 km|Single mode fiber for connecting infras­tru­cture outdoors. Used for MANs, ISPs, or MSPs.|

### OSI Troubl­esh­ooting

|   |   |   |
|---|---|---|
|**Layer**|**Command**|**Purpose**|
|**Physical**|`ip -br -c link`|Is your physical interface up? Gives you detailed inform­ation on your NICs and virtual NICs.|
|**Data Link**|`ip neighbor show`|Displays the Address Resolution Protocol (ARP) table. Shows the IP and MAC addresses of computers you can reach on the network.|
|**Network**|`ip -br -c address show` or   <br>  <br>`ip -br -c a'`|Displays your network cards, their connection status, the IP address and CIDR. Make sure you have a valid IP address on your LAN NIC.|
||`ping <we­bsite or IP addres­s>`|Ping the device you're trying to connect to, or ping a commonly used server like Google's DNS (8.8.8.8) .|
||`traceroute <we­bsite or IP addres­s>`|Sends a packet out to a destin­ation using Time to Live (TTL). The end result is a list of routers that the packet interacted with on the way to the destin­ation|
||`ns lookup <we­bsite name>`|Checks recognized DNS entries on your server. Make sure the IPs match up with results from ping|
|**Transport**|`ss -tunlp4`|_Socket Statistics_ gives you a list of connec­tions and ports on your server. Use it to make sure you are able to connect to certain devices**-t**  ­ ­ ­ Show TCP ports**-u**  ­ ­ ­ Show UDP ports**-n**  ­ ­ ­ Do not try to resolve hostnames**-l**  ­ ­ ­ Show only listening ports**-p**  ­ ­ ­ Show processes that are using a particular socket**-4**  ­ ­ ­ Only show IPv4 sockets|
|**Session**|SSH or RTP|Get a device to accept your SSH session or initialize an RTP session from a camera. Keep in mind, RTP is different from RTSP.|
|**Presentation**|HTML, RTSP|Connect to a camera's webpage, or query a camera stream through VLC.|
|**Application**|Using the program|Can you interact with a webpage? Can you view DS logs once it's running? Good! Then you've confirmed the _Applic­ation_ is up and running.|

### Network Hardware

|   |   |
|---|---|
|**Network Interface Controller (NIC)**|The ethernet jack on a computer.|
|**Wireless Network Interface Controller**|Same thing as a NIC, but it uses radio waves to connect to an access point instead of a cable.|