  

### Mapping a Network

> u should always ask what is your scope of penetration testing process

> First if u have a physical testing in your scope u should see the cameras , gardes , gate security ..etc

> seconde u should do some Osint to your target and gathering as u can as information

> third u can did some social eng ;)

> with sniffing u can did some passive recon and u can see the network traffic

> u can take advantage with ARB (address resolution protocol ) , that use to maps IP addresses to MAC adresses

> ICMP ( internet control message protocol ) if any packets dropped the ICMP is the answer

> Use Ping to see if this IP is alive

  

- to capture the network traffic use a Wireshark ⇒ _==open it and click on start button==_ & u can see the endpoint of u’r scan

  

- and to scan for arp protocol ⇒ _==sudo arp-scan -I tap0(or any intrface) -g <ip /subnet>==_

  

- u can ping multi interface using fping ⇒ _==fping -I tap0(or any intrface) -a(all live ip )==_

  

- another tool u can use nmap ⇒ _==nmap -sn <ip /subnet>==_

  

  

### Port Scanning

we know that the port is open there using the TCP three way handsheck ⇒

> if we send the SYN and the server return with RST+ACK ⇒ so the Port is closed

  

- we can use nmap with file of our ip’s ⇒ _==nmap -iL <ip file>==_

> if u scan with nmap and no result back to u try to scan with flag ⇒ _==-p-==_

> if u have a UDP ports u can use _==-sUV==_