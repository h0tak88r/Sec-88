- ==ZigBee== Standards
    
    - ZigBee is a standard for ==**wireless personal-area networks**== (WPANs).
    - Developed as an ==**open global standard.**==
    - Based on the universal **==IEEE 802.15.4 standard.==**
    - ==**Penetration Testers**== and ==Ethical Hackers== use ==SDR (====**Software Defined Radio)**== to spot the ==**vulnerabilities**== in the Wireless Devices.
    
- A ==Coordinator==
    
    - A parent node that starts up a network.
    - The ==coordinator== performs the following functions:
    
    1. Selects the ==channel== to be used by the network.
    2. Coordinates your ==Personal Area Network (PAN).==
    3. Permits other devices to ==join== or ==leave== the ==network==.
    4. Assigns how addresses are allocated to ==nodes== or ==routers==.
    
- Advantages of choosing ==**ZigBee**==
    
    - The provision of ==long battery lifetime.==
    - The support of ==a large number of nodes== (up-to 65000) in a network.
    - The easy deployment.
    - The ==low costs== and global usage.
    
- ==ZigBee== Uses
    

==ZigBee== Topologies

- **==ZigBee==** home automation profile [ ==Startup Attribute Sets (SAS==) ]
    
    - 0x5A 0x69 0x67 0x42 0x65 0x65 0x41 0x6C 0x6C 0x69 0x61 0x6E 0x63 0x65 0x30 0x39 [Default Trust Center Link Key]
    
    ⚠️
    
    From a security standpoint
    
    - 0x01 (True)
    - This flag enables the use of default link key join as a fallback case at startup time.
    
- ==ZigBee== Protocol Architecture
    
- **==ZigBee==** Security
    
    ### Security services provided by ZigBee include:
    
    - key establishment
    - Secure networks
    - key transport
    - Frame protection
    
- **==ZigBee==** Security Keys
    
    ### ==**Network key**==
    
    - Used to secure ==broadcast communication.==
    - This ==128==-bit key is shared among ==all devices== in the network.
    - Network keys are stored by the ==Trust Center==, but only one network key is the ==active network key.==
    - The current active network key is identified by a sequence number and may be used ==by the NWK and APL layers of a device.==
    - A device must acquire a network key via ==key-transport or pre-installation.==
        
        ### ==Link key==
        
    - Used to secure ==unicast communication on Application layer.==
    - This ==128-bit== key is shared only ==between two devices.==
    - Link keys are acquired either via ==key-transport, key-establishment, or pre-installation.==
    
- Application Support Sublayer Security
    
    The APS layer is responsible for:
    
    - The ==proper protection== of the frame.
    - Allows frame security to be based on ==link keys== or the ==network key.==
    - Checks if the frame gets protected on ==NWK layer== (If the active network key should be used for frame protection).
    - Providing applications and the ZDO with ==key establishment, key transport, and device management services.==
    
- Target ==Attacks==
    
    ⚠️
    
    Sink Attacks (Sinkhole)
    
    - Take place when a malicious node announces a route to be the shortest path.
    - Since all routing algorithms select the shortest path, it will attract more network traffic to be tunneled toward it.
    
    ⚠️
    
    Source Attacks
    
    - The adversary compromises one legitimate node to act as a black hole node.
    - A node that selectively drops received packets or all received packets to trick other neighboring nodes to search for another rout as the previous one has failed.
    
    ⚠️
    
    Neighbor Attacks
    
    - A malicious node sends HELLO message with a high transmission power,
    - The receiving nodes consider this node as its neighbor and will send the sensed packet data in return,
    - A huge amount of energy will be wasted, and congestion might occur consequently.
    
- Member ==Attacks==
    
    ⚠️
    
    Outcast attacks (non-member)
    
    - The attacker node is not part (non-member) of the network but threats the network.
    
    ⚠️
    
    Insider attack (member)
    
    - The malicious node is part of the network either by compromising it or the attacker has loaded a fake profile and asked to join the network.
    
- Security Best Practice ==Recommendations==