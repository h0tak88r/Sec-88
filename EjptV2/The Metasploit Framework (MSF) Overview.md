  

### _==**Metasploit Framework Overview**==_

> an open source robust penetration testing and exploitation framework tool and the largest database of publicly ,tested exploits

> it’s can automate every stage of the penetration testing life cycle

> ==_Armitage_== , it’s exactly like the MSF

- ==_Metasploit Framework Architecture_==

> `Exploit modules` ⇒ used with payload ( the code we used and upload to target system to take advantage) , what is give us a revers shell or what we want is the payload not the exploit

> `Encoder Modules` ⇒ Used to encode payloads in order to avoid Anti virus detection .

> `Nops Modules` ⇒ Used to ensure that the payload size is consistent , and ensure that the target system is stable , to avoid target crash

> `Auxillary Modules` ⇒ isn’t or cannot be paired with a payload , is used to perform additional functionality like : port scanning and enumeration

- ==_**Payload Types**_==

1. `_Non-Staged Payload_` ⇒ Payload that is sent to the target system as i along with the exploit
2. `_Staged Payload_` ⇒ sent to the target in tow parts

1. ==first-part (stager)== ⇒ contains a payload that is used to establish a reverse connection back to the attacker , and establish a stable communication channel between the attacker and target

2.==seconed part (stages)== ⇒ is responsible to execute arbitrary commands on the target , or providing us with Meterpreter session.

1. `Meterpreter Payload` ⇒ is advanced multi-functional payload that is executed in memory on the target

> It communicates over a stager socket and provides an attacker with an interactive command interpreter on target system

- U can access it on ⇒ `/usr/share/metasploit-framework/modules`

  

- ==**_Penetration Testing With The Metasploit Framework_**==

> Penetration Testing Execution Standard (PTES)

  

|PT Phase|Metasploit framework implementation|
|---|---|
|Information gathering& enum|Auxiliary Modules|
|Vulnerability scanning|Auxiliary Modules && Nessus|
|Exploitation|Exploit Modules & payload|
|Post Exploitation|Meterpreter|
|Privilege Escalation|Post Exploitation Modules && meterpreter|
|Maintaining Persistent access|Post Exploitation Modules && Persistent|

  

  

### ==_**Metasploit Fundamentals**_==

  

- ==Installing & Configuring The Metasploit Framework==

> `msfdb` ⇒ it’s the database of the metasploit

> `sudo systemctl enable postgresql` ⇒ to setup the the postwagger database

> `sudo systemctl start(or status) postgresql` ⇒ to start it

- `sudo msfdb`
- `msfconsloe`

  

==Metasploit Fundamentals==