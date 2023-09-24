  

- **_==Port Scanning & Enumeration with Nmap==_**
    
    > After u do your scan save the result on XML ⇒ `-oX` ⇒ to use this file on Msfconsole
    
    > start msfconole && db_import <the file name>
    > 
    > whene can upload the file or nmap resutl
    
      
    

  

## _==**Enumeration**==_

- _==FTP Enumeration==_

> `FTP` ⇒ File transfer protocol that uses TCP port 21 and is used to facilitate file sharing between a server and client/clients .

> To authentication ⇒ `use username and password`

  

- _==FTP Enumeration==_
    
    > _==Port scan to find FTP==_
    
    1. `nmap <ip> -sV` ⇒ to find if the Ftp is there
    2. `msfconsole`
    3. `use auxiliary/scanner/portscan/tcp` ⇒ that to scan for open ports on msfconsole
    4. `set RHOST <Target ip>` && `run`
    
    > _==To identify the version of FTP==_
    
    1. `search type:auxiliary name: ftp` ⇒ to search for ftp services
    2. use `auxiliary/scanner/ftp/ftp_version`
    3. `set RHOST <target ip>` && `run` ⇒ so after we detect the version of the ftp , we can search for exploit or vuln on it
    
    > _==To bruteforce the login==_
    
    1. now to bruteforce the login ⇒ `use auxiliary/scanner/ftp/ftp_login`
    2. `set RHOST <target ip>` && `set User_FILE /usr/share/metesploit…/data/worldlist/common_user.txt` &&`set PASS_FILE /usr/share/metesploit…/data/worldlist/unix_password.txt` && `run`
    3. after u find a cred ⇒ `ftp <target ip >` , then enter the cred
    4. to get any file ⇒ `get <filename>`
    
    > _==To try login anonymes==_
    
    1. `Use auxiliary/scanner/ftp/anonymous`
    2. `set RHOST <target ip>` && `run`
    
      
    
      
    

  

- **==_SMB Enumeration_==**

> _==SMB ( Server Message Block )==_ ⇒ Network file sharing protocol that is used to facilitate the sharing of files and devices between computers on a local network , also known as a LAN .

> SMB uses port `445 on the TCP stack` , on older version of windows run on top of the `NetBIOS Protocol using port 139` .

> SAMBA is the linux implementation of SMB , essentially allows windows system access linux shares and devices and vice versa

  

- **==_SMB Enumeration_==**
    
    - `nmap <ip> -A` ⇒ to identify which os we play with
    - `msfconsole` && `search type:auxiliary name:smb` && `use auxiliary/scanner/smb/smb_version` && `set all the default opttions` && `run`
    
    > so after u identify what is the system u work with (SAMBA || SMB) and the version of it
    
      
    
    - ==To enumerate the users== ⇒ `use auxiliary/scanner/smb/smb_enumuser` && `set all the default opttions` && `run`
    
      
    
    - ==To enumerate the shares on SMB server ⇒== `use auxiliary/scanner/smb/smb_enumshares` &&`set showfiles true` && `set all the default opttions` && `run`
    
      
    
    - ==To bruteforce the login== ⇒ `use auxiliary/scannersmb/smb_login` && `set smbuser <the name u get from enumerate user>` && `set PASS_FILE /usr/share/metesploit.../data/worldlist/unix_password.txt` && `set all the default opttions` && `run`
    - `smbclinet -L \\\\<ip>\\ -U <username>` && `enter the password`
    
    > if we want to access just specific Sharefile just remove -L and after \\ enter the share file name .
    
      
    
      
    
      
    
      
    
      
    

  

  

- **==Web Server Enumeration==**

> Web server ⇒ is software that is used to serve website data on the web .

> Utilize HTTP( hypertext transfer protocol) to facilitate the communication between clients and web server .

> HTTP is an application layer protocol that Utilizes TCP port 80 for communication .

> example ⇒ Apache , Nginx ,Microsoft IIS

> When u implement the SSL certificate For encryption communication , then the port will become 443 _==HTTP ⇒ PORT 80==_ , _==HTTPS ⇒ PORT 443==_

  

- **==Web Server Enumeration==**
    
    - `nmap <ip> -sV -O` ⇒ To identify the service running
    - `msfconsole` && `search type:auxiliary name:http` && `use auxiliary/scanner/http/http_version` && `set all default opttions` && `run` ( if the app use https ⇒ `set SSL true`
    
      
    
    - _==To enumeration the headers==_ ⇒ `use auxiliary/scanner/http/http_header` && `set all default opttions` && `run`
    
      
    
    > `robots.txt` ⇒ is txt file that stored at the root of a web server and is used to prevent search engines from indexing specific directories and files that hosted on that web server .
    
    > `directory listing` ⇒ is configuration that is native to Apache as well as a few other web server , it’s allows you to store files within a directory , and they can be indexed and accessed within that directory , so if u want to host files for download to the public , you typically have them in a directory and then enable dirctory listing .
    
      
    
    - _==To==_ _==enumeration the robots.txt file==_ _⇒_ `use auxiliary/scanner/http/robots_txt` && `set all default opttions` && `run`
    
      
    
    - ==To bruteforce dirctory== ⇒ `use auxiliary/scanner/http/dir_scanner` && _( the default bruteforce file ⇒ use/share/metasploit../data/wmap/wmap_dirs.txt )_ && `set all default opttions` && `run`
    
      
    
    - ==To bruteforce the Files== ⇒ `search files_dir` &&`use auxailiary/scanner/http/files_dir` && _( the default bruteforce file ⇒ use/share/metasploit../data/wmap/wmap_files.txt )_ && `set all default opttions` && `run`
    
      
    
    - To bruteforce the login ⇒ `use auxiliary/scanner/http/http_login` && `set auth_uri <dirctory that have the login>` && `unset userpass_file` && `set user_file /usr/share/metasploit…/data/wordlists/namelist.txt` &&`set pass_file /usr/share/metasploit…/data/wordlists/unix_password.txt` && `set verbose false` && `set all default opttions` && `run`
    
      
    
    - ==To enumeration the valid user== ⇒ `use auxiliary/scanner/http/apache_userdir_enum` && `set user_file /usr/share/metasploit…/data/wordlists/common_users.txt` && `set all default opttions` && `run`
    
    > u can take the output from here and use it on login bruteforce step
    

  

  

- **==_MySql Enumeration_==**

> it’s a open source relational database management system based on SQL ( structured query language)

> used to store records , customer data , and is most commonly deployed to store web application data .

> ==MySql utilizes TCP port 3306 by default==

  

- **==_MySql Enumeration (make a work space for each test )_==**
    
    - `nmap <ip> -sV -O` ⇒ to perform the servesis that running on target system
    - `msfconsole` && `search type:auxiliary name:mysql` && `use auxiliary/scanner/mysql/mysql_version` && `set all default opttions` && `run`
    
      
    
    - ==To bruteforce mysql login== ⇒ `use auxiliary/scanner/mysql/mysql_login` && `set username root` && `set pass_file /usr/share/metaspolit…/data/worldlist/unix_password.txt` && `set verbose false` &&`set all default opttions` && `run`
    
      
    
    - ==To Enumeration the MySql== ⇒ `use auxiliaary/admin/mysql/mysql_enum` && `set username` && `set password` && `set all default opttions` && `run`
    
      
    
    - ==To execute sql queries and interact with the database== ⇒ `use auxiliary/admin/mysql/mysql_sql` && `set username` && `set password` && `set SQL <sql command u want to run>;` && `set all default opttions` && `run`
    
      
    
    - ==To dumb all the database data== ⇒ `use auxiliary/scanner/mysql/mysql_schemadump` && `set username` && `set password` && `set all default opttions` && `run`
    - u can use this ⇒ `mysql -h <ip> -u <username> -p ,enter the password >`
    

  

  

  

- **==_SSH Enumeration_==**

> SSH ( secure shell) is a remote administration protocol that offers encryption and is the successor to telnet

> used to remote access to servers and systems

> On Port 22

> the difference between the SSH and Telnet , that the SSH is encrypted , so when u connect with the server the communication chanel will be secure , rather than the telnet , the communication chanel would be unencrypted , which means that any attacker can sniff the traffic

  

- **==_SSH Enumeration_==**
    
    - `nmap <ip> -sV -O` ⇒ to perform the servesis that running on target system
    - `msfconsole` && `workspace -a SSH_enum` && `search type:auxiliary name:ssh` && `use auxiliary/scanner/ssh/ssh_version` && `set all default opttions` && `run`
    
      
    
    - ==To do a bruteforce to ssh login== ⇒ `use auxiliary/scanner/ssh/ssh_login` && set user_file
    
    `/usr/share/metaspolit…/data/worldlist/common_user.txt` && set pass_file `/usr/share/metaspolit…/data/worldlist/common_password.txt` && `set all default opttions` && `run`
    
    > u can login using ⇒ `ssh <username>@<ip> then enter the password`
    
      
    
    - _==To enumeration users==_ ⇒ `use auxiliary/scanner/ssh/ssh_enumusers` && set user_file`/usr/share/metaspolit…/data/worldlist/common_user.txt` && `set all default opttions` && `run`
    
      
    
      
    

  

  

- ==**_SMTP Enumeration_**==

> STMP ( Simple Mail Transfer Protocol) ⇒ is a communication protocol that is used for the transmission of email

> SMTP on Port 25 can be also configured on port 465 and 587

  

- ==SMTP Enumeration==
    
    - `nmap <ip> -sV -O` ⇒ to perform the services that running on target system
    - `msfconsole` && `workspace -a smtb_enum` && `search type:auxiliary name:smtb` && `use auxiliary/scanner/smtb/smtb_version` && `set all default opttions` && `run`
    
      
    
    - ==To enumeration SMTB users== ⇒ `use auxiliary/scanner/smtb/smtb_enum` && set user_file `/usr/share/metaspolit…/data/worldlist/unix_user.txt` && `set all default opttions` && `run`