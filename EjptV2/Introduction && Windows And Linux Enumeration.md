  

  

### _==Post-Exploitation==_

- _==Introduction To Post-Exploitation==_

> _==Post-exploitation==_ is the final phase of the penetration testing process and consist of the tactics , techniques and procedures that attackers/adversaries undertake after obtaining initial access on a target system

> In other words , post-exploitation involves what you do or have to do once u gain access to the target system .

> Post-exploitation will differ based on the target operating system as well as the target infrastructure .

  

- ==Post-Exploitation Methodology==

  

  

- `Post-Exploitation Methodology`
    
    1. ==_Local Enumeration_==
        - [ ] Enumerating System Information
        - [ ] Enumerating Users And Groups
        - [ ] Enumerating Network Information
        - [ ] Enumerating Services
        - [ ] Automating Local Enumerating
    2. ==_Transferring Files_==
        - [ ] Setting Up A web server with python
        - [ ] Transferring Files To Windows Target
        - [ ] Transferring Files To Linux Target
    3. ==_Upgrading Shells_==
        - [ ] Upgrading Command Shells To Metepreter
        - [ ] Upgrading TTY Shells
    4. ==_Privilege Escalation_==
        - [ ] Identifying PrivEsc Vulns
        - [ ] Windows PrivEsc
        - [ ] Linux PrivEsc
    5. ==_Persistence_==
        - [ ] Setting up persistence on windows
        - [ ] Setting up persistence on linux
    6. ==_Dumping & Cracking Hashes_==
        - [ ] Dumping & Cracking Windows Hashes
        - [ ] Dumping & Cracking Linux Hashes
    7. Pivoting
        - [ ] Internal Network Recon
        - [ ] Pivoting
    8. Clearing your tracks
        - [ ] Clearing your tracks on Windows & Linux
    

  

  

  

### ==_**Windows Local Enumeration**_==

  

- ==_Enumerating System Information_==

> After gaining Access to target system , it always important to learn more about the system

> _What are we looking for_ ⇒ Hostname , OS Name ( win 7 ,8 ..) , OS Build & service Pack (Windows 7 SPI 7600 ) ,OS Architecture (x64/x86) , installed updates/Hotfixes

  

- Enumerating System Information
    
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports
    - Find the services is running and try to exploit it
    - After we gain access to target system via exploit the services running
    - To obtain the hostname ⇒ `getid`
    - To get OS Name ( win 7 ,8 ..) , OS Build & service Pack (Windows 7 SPI 7600 ) ,OS Architecture (x64/x86) ⇒ `sysinfo`
    - `shell` && enum hostname ⇒ `hostname` && to enum the system information and the hotfixes(updates) ⇒ `systeminfo`
    - `wmic qfe get caption,Description,HotFixID,InstalledON` ⇒ To enum detailed info related to HotFixes ( The Updates that installed on system )
    
      
    

  

- _==Enumerating Users & Groups==_

> _What are we looking for_ ⇒ Current user & privileges , Additional user information , Other users on the system , Groups , Members of the built-in administrator group

  

- Enumerating Users & Groups
    
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports
    - Find the services is running and try to exploit it
    - After we gain access to target system via exploit the services running
    - To obtain the current user & privileges ⇒ `getid`
    - `getprivs` ⇒ to list all privileges that the administrator have
    - On msfconsole ⇒ `search logged_on` & `use post/windows/gather/enum_logged_on_users` && `set session <number of session>` ⇒ that will return with the current logged user , and recently logged users
    - `shell` && `whoami` ⇒ To enum the hostname and privileges
    - `/priv` ⇒ to list all privileges u have && `query user` ⇒ to list all logged user
    - `net users` ⇒ To list all user account &&& If u want to learn more about a user ⇒ `net user <name of user >`
    - `net localgroup` ⇒ To list all group in the system
    - `net localgroup <users name>` ⇒ To list all users that are part of this group .
    
      
    

  

  

- _==Enumerating Network Information==_

> _What are we looking for_ ⇒ ( Current IP address && network adapter ) && Internal network && TCP/UDP services running and their respective ports && Other hosts on the network && Routing table && Windows Firewall state

  

- Enumerating Network Information
    
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - `shell` && `ipconfig` ⇒ To Obtain The current adapters connected to this system , ipv4 , ipv6 , Subnet Mask , Default gateway .
    - `ipconfig /all` ⇒ To list all info regarding all IP’s , hostname , DNS Suffix , IP routing functionality , Mac address ……. and a lot lot lot .
    - `route print` ⇒ we will see the table of all IP’s on system and the gateway of them …
    - To see what other systems are available on this network ⇒ `arp -a`
    - `netstat -ano` ⇒ to list all services are running or listening on the system .
    - `netsh advfirewall firewall dump` && `netsh advfirewall show allprofiles` ⇒ to list all firewall in the system
    

  

- ==_Enumerating Processes & Services_==

> _What are we looking for_ ⇒ ( Running processes & services ) && scheduled tasks

> _Process_ ⇒ is an instance of a running executable (.exe) or program

> _Service_ ⇒ is a process which runs in the background and dose not interact with the desktop .

> That’s Useful when we have a metepreter session that’s work with some process , but these process is not stable , so we can migrate it to another process , so we need to obtain the process id to do that , that what we can actual purpose of enum process .

  

- Enumerating Processes & Services
    
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - `ps` ⇒ will list all process on the system
    - `pgrep < process name >` ⇒ will return with the process id , which we will use to migrate it to another ( recommended using explorer.exe , if u want a stable metepreter session migrate a explorer.exe )
    - `migrate <process id >` ⇒ that will migrate the process , so now metepreter session will work with new process , and if we migrate a 64-bit process , the metepreter session will be a 64-bit .
    - `shell` && `net start` ⇒ that will list all background services running
    - `wmic service list brief` ⇒ it’s same as net start
    - `tasklist /SVC` ⇒ that will list all services running under the process and process , one of the important command
    - `schtasks /query /fo LIST` >> `alot-of info.txt` ⇒ to list all schedule tasks
    
      
    

  

  

- _==Automating Windows Local Enumeration==_

> _==JAWS ( just another windows (enum) script )==_ ⇒ is powershell script designed to help penetration testers , quickly identify potential privEsc vectors on windows system .

💡

[https://github.com/411Hall/JAWS](https://github.com/411Hall/JAWS)

- Open the [script.py](http://script.py) && `ctrl+shift+alt` ⇒ to save it on clipboard && make a file and paste it on the file called it `JAWS.ps1` ⇒ here we can use any script on internet without have a internet connection on the lab env
- open metepreter session , `mkdir Temp` && `cd c:\\ && upload /root/Desktop/JAWS.ps1`
    - `powershell.exe -ExecutionPolicy Bypass -File .\JAWS.ps1 -OutputFilename JAWS.txt` ⇒ To run it on target system , so what happen here we tell powershell to execute the JAWS script and the output of this execution save it on other text file

  

- Automating Windows Local Enumeration
    
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - with msfconsole , on metepreter session ⇒ `show_mount` ⇒ to list all drive connected to the system .
    
      
    
    - `search win_privs` && `use post/windows/gather/win_privs` && `set session 1` &&`run` ⇒ To get the privis , and a lot like that
    - `post/windows/gather/enum_loggod_on_user`
    - `search checkvm` && `use post/windows/gather/checkvm` ⇒ to know if it’s vm or not
    - `search enum_applications` && `use post/windows/gather/enum_applications` ⇒ that will enum all applications installed on the server
    - `search enum_computers` && `use post/windows/gather/enum_computers` ⇒ that will return with all computers are connected to the server , if it part of network domain
    
      
    

  

  

  

### _**==Linux Local Enumeration==**_

  

- ==Enumerating System Information==

> _What are we looking for_ ⇒ Hostname , Distribution ( ubuntu , arch , kali ….. ) & distribution release version , Kernel version & architecture , CPU information , Disk information & mounted drives , installed packages/software .

  

- _Enumerating System Information_
    
    - `ipconfig` && `eth1` ⇒ that’s the target ip , make sure to change the ip based on subnet ( 192.168.23.12 ⇒ ==192.168.23.====13== )
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - `/bin/bash -i` ⇒ to get a bash terminal
    - On metepreter ⇒ `sysinfo` ⇒ that will give u a basic idea of what’s running on target system
    - On bash ⇒ `hostname` ⇒ that will return with the hostname
        
        - `cat /etc/issues` ⇒ to obtain the distribution & distribution release version
        - `cat /etc/*release` ⇒ that will display a lot regarding to the system and target
        - `uname -a` ⇒ that will display a lot
        - `env` ⇒ that will return with environment variable
        - `lscpu` ⇒ will return a lot a lot of cpu information
        - `df -h` ⇒ to display the drives on the target system
        - `df -ht ext4` ⇒ that will return with the actual drive that have the linux system
        - `dpkg -l` ⇒ to list all package installed on system
        
          
        
          
        
    

  

  

- ==Enumerating Users & Groups==

> _What are we looking for_ ⇒ Current user & privileges , Other Users on the system , Groups

  

- _Enumerating Users & Groups_
    
    - `ipconfig` && `eth1` ⇒ that’s the target ip , make sure to change the ip based on subnet ( 192.168.23.12 ⇒ ==192.168.23.====13== )
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - On Metepreter ⇒ `getuid` ⇒ will display the id of type of user ( 0 ⇒ root )
    - On bash ⇒ `whoami` ⇒ that will tell u the type of user
        
        - `groups <hostname >` ⇒ to see what the group the user belong to .
        - `cat /etc/passwd` ⇒ to list all users and services account ( to differentiate between the users and service account ⇒ ==user== end with /bin/bash , ==Service account== end with /usr/sbin/nologin
        - `groups` ⇒ to list all groups on target
        
          
        
    

  

- ==_Enumerating Network Information_==

> _What are we looking for_ ⇒ Current IP address & network adapter , Internet network , TCP/UDP services running and their respective ports , Other hosts on the network

  

- Enumerating Network Information
    
    - `ipconfig` && `eth1` ⇒ that’s the target ip , make sure to change the ip based on subnet ( 192.168.23.12 ⇒ ==192.168.23.====13== )
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - ==_On Metepreter_== ⇒ `ifconfig` ⇒ that will list all info u need regarding the IPS and network interfaces
        - `netstat` ⇒ will list all current TCP/UDP services that running on target system
        - `route` ⇒ to display the routing table ( the key information here is the gateway , because maybe it will be the router or
        - `arp` ⇒ that will display all information regarding to other system that are connected to the network
    - ==_On shell_== ⇒ `shell` && `/bin/bash -i` ⇒ to switch to linux terminal
        - `ip a s` ⇒ that will list all info about target interfaces
        - `cat /etc/networks` ⇒ that will list the network endpoint configuration
        - `cat /etc/hosts` ⇒ return with all hosts
        - to display the DNS configuration ⇒ `cat /etc/resolv.conf`
    

  

  

- ==Enumerating Processes & Cron Jobs==

> _What are we looking for_ ⇒ Running services , Cron Jobs

  

- Enumerating Processes & Cron Jobs
    
    - `ipconfig` && `eth1` ⇒ that’s the target ip , make sure to change the ip based on subnet ( 192.168.23.12 ⇒ ==192.168.23.====13== )
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - ==On Metepreter== ⇒ `ps` ⇒ To list all Processes
    - ==On Bash== ⇒ `top` ⇒ that will list all processes in dynamic utility way ( is like a live scan )
        - `crontab -l` ⇒ to list all cron jobs the target have
        - `ls -al /etc/cron*` ⇒ that will return with all file that have cron on it’s name like , ( daily cron , weekly cron , monthly cron )
    
      
    

  

  

  

- ==Automating Linux Local Enumeration==
    
    - `ipconfig` && `eth1` ⇒ that’s the target ip , make sure to change the ip based on subnet ( 192.168.23.12 ⇒ ==192.168.23.====13== )
    - `nmap -sS sV -O <target ip>` ⇒ scan for open ports and what services are running on this ports .
    - Find the services is running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - ==`LinEnum`==
        
        > is bash script that automates common linux local enumeration checks
        
        - `https://github.com/rebootuser/LinEnum`
        - copy the script from the github && `ctrl+shift+alt` ⇒ to save it on clipboard && make a file and paste it on the file called it `lin_enum.sh` ⇒ here we can use any script on internet without have a internet connection on the lab env
        - open metepreter session && `cd tmp` && `upload /root/Desktop/lin_enum.sh`
        - `chmod +x lin_enum.sh` && `./lin_enum.sh` ⇒ that will return with all info we need
        
          
        
    - `search enum_configs` && `use post/linux/gather/enum_configs` ⇒ that’s enum all configuration files and some important info
    - `search enum_network` && `use post/linux/gather/enum_network` ⇒ will return with all network information
    - `search enum_system` && `use post/linux/gather/enum_system` ⇒ that will start gathering all system information
    - `search checkvm` && `use post/linux/gather/checkvm` ⇒ to know if the target is vm or not