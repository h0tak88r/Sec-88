  

### Services and servers

  

- ==_**`nmap --script vuln <ip>`**_==

  

### SMB

  

- First Service ⇒ _**==SMB==**_ ⇒ windows implementation of a file name (_SMB ⇒ Server Message Block_ )

> it’s on Ports 139,445 which is based on a windows server there where SMB or CIFS hangout && Port 139 which is a NetBIOS is a bigger part of SMB is still exist in old version of windows , usually used to set up the session for SMB

  

- `==_**Smb enum with nmap**_==`
    
    1. if u find a SMB , first use nmap script with it ⇒ ==**_nmap -pa445(the windows server port ) - -script smb-protocols <ip>_**== ,,,,,,,, **_“ we will see the version of it “_**
    2. to see info about role account , type ..etc ⇒ ==**_nmap -pa445(the windows server port ) - -script smb-security-mode <ip>_**==
    3. to enum the session ⇒ ==**_nmap -pa445(the windows server port ) - -script smb-enum-sessions <ip>_**==
    4. _==smb-ls==_ && _==script-args==_ ==_smbusername=administrator_==_==,==_==_smbpassword=smbserver_771_==_==(to use username and password)==_
    5. so after u see the version of the SMB now u can play with smbmap ⇒ ==_**$ smbmap -u <gusset || administrator > -p “ “ -d . -H <ip>**_== -u (username) , -p (password) , -d (directory) , -H (Host)
    6. so let’s login and try to do code execution ⇒ ==_**$ smbmap -H <ip> -u <gusset || administrator > -p “ “ -x ‘<command>’**_==
    7. we can connect with drive on it using ⇒ ==_**$ smbmap -H <ip> -u <gusset || administrator > -p “ “ -r ‘c$’**_==
    8. now we see like a password file so how to grep it ⇒ **_==First we will make a file && then we will upload it to the c drive using ⇒ - -upload ‘/root/file’ ‘C$\file’==_**
    9. to download file now from the drive ⇒ _==- -download ‘C$\password.txt’==_
    10. **_==- -script smb-os-discovery==_**
    11. **_==- -script smb-enum-users==_**
    12. **_==- -script smb-enum-shares==_**
    

- **Windows Recon: SMBMap LAB Solution video**

  

  

- `==Metasploit==` ==⇒== _it’s abc cyber security_
    
    > u can see it have alot of tools , exploit , auxiliary (auxiliary/scanner) , nops ….. etc
    
    > to bruteforce login ⇒ **_==use auxiliary/scanner/smb/smb_login==_** && **_==info==_** && **_==options==_** && **_==set rhost <ip>==_** && **_==set pass_file (worldlist for pass to use when bruteforce )<path-of-worldlist> && set smbuser <user>==_**
    
    > **_==use auxiliary/scanner/smb/pipe_audItor && set smbuser && set smbpass && set rhost==_**
    
    > **_==options==_** ⇒ to see the options on it , **_==use==_** ⇒ act like cd , **_==set rhost==_** ⇒ to enter the ip , **_==run || exploit==_** ⇒ to attack
    
    > use auxiliary/scanner/smb_enumshares
    
      
    

  

  

- **_==nmblookup==_** _⇒ to scan about netbios_
    
    > **_==smbclient -L <ip> -N==_** ⇒ to list what u can connect , _**If u see IPC$ that 80% u can connect**_
    
    > now after get the share are no need auth ⇒ **_==smbclinet //<ip>/p<public-share> -N && cd <dir> && get <file>==_**
    
    > **_==smbclient //<ip>/user -U <username> && enter the password ⇒==_** to login
    

  

  

  

- **_==rpcclinet -U “” -N <ip>==_** ⇒ to connect with null username and no password
    
    1. **_==srvinfo==_** ⇒ to list information about server
    2. _==enumdomusers==_
    3. _==lookupnames <user-name>==_
    

  

- ==enum4linux== ⇒ its powerfull tools u can use to scan
    
    > **_==enum4linux -o <ip>==_** ⇒ to list info about operating system
    
    > **_==enum4linux -U <ip>==_** ⇒ to list users
    
    > _**==-S==**_ ⇒ to enum shares
    

  

- **_==hydra -l <username> -P <worldlist> <ip> <protocol>(smb)==_** ⇒ to bruteforse about login

  

💡

If u found the password using smbmap to login ⇒ **_==smbmap -H <ip> -u <username> -p <password>==_**

  

- **Samba Recon: Dictionary Attack** **LAB Solution video**

https://drive.google.com/file/d/12mYAZSePRW5EEkEwnk_CqbHIuCke4QcY/view?usp=sharing

  

  

---

---

---

  

### FTP

  

> It is stand of “ `File Transfer Protocol` “ on Port 21

> it’s using to save file on server and it has a access to memory

  

- `_**ftp <ip>**_` ⇒ to login with ftp protocol

  

- `hydra -L user_linux.txt -P /unix_pass.txt <ip> <protocol>` ⇒ to bruteforce the username and the password treing to login

  

- `==nmap --script=ftp-brute --script-args userdb=/~/users.txt -p 21 <ip>==` ⇒ to bruteforce the password based on users worldlist

  

  

- **ProFTP Recon: Basics** **LAB Solution video** **Lab**

https://drive.google.com/file/d/1g0mrmwQCd--qLl0QxuddT7hQ9hsNYqJy/view?usp=sharing

  

- `==nmap <ip> -p 21 --script=ftp-anon==` ==⇒ we can use that to try login anonymous to the ftb , we can try it if it allowed==

> _if that allowed , u can login using anonymous as a user and ‘null’ as a password_

  

  

### SSH

  

> `ssh <username>@<ip>`

- to enum all algorithms related with ssh ⇒ `nmap <ip> -p <port> - -script=ssh2-enum-algos`
- to find a ssh rsa-key ⇒ `nmap <ip> -p <port> - -script=ssh-hostkey - -script-args ssh_hostkey=full`
- to find some auth cred ⇒ `nmap <ip> -p <port> - -script=ssh-auth-methods - -script-args="ssh.user=admin"(try usersname related with org)`

  

- to bruteforce the password using hydra ⇒ `hydra -L <username> -P /rockyou-pass.txt <ip> ssh`
- to bruteforce the password using nmap ⇒ `nmap <ip> -p <protocol> - -script=ssh-brute - -script-args userdb=<wordlist of usernam>`
- u can use Metasploit to bruteforce the login ⇒ `msfconsol && use auxulary/scanner/ssh/ssh_login && set rhost && set userpass_file /usr/share/wordlist/metasploit/root_userpass.txt && set verbose true` && run

  

  

### HTTP

  

> first when we see a port 80,443 , we have a http,https , so open the ip on web browser

- `whatweb <ip>` =⇒ to see some basic info about it
- `dirb <url>` ⇒ bruteforce to directors
- `browsh - -startup-url <url>` ⇒ that will open the website in your command line

  

- To enum with nmap script ⇒ `nmap <ip> -sV -p 80 - -script=http-enum`
- To return with all headers ⇒ `nmap <ip> -sV -p 80 - -script=http-headers`
- To dig in path in website ⇒ `nmap <ip> -sV -p 80 - -script=http-methods - -script-args http-methods.url-path=/<path>/`

  

> in most cases when u see the app hosting on apache , The app on ubuntu

  

- if the app hosting in Apache (Metasploit)⇒ msfconsole
    
    1. To scan about version ⇒_`use auxalari/scanner/http/http_version & set rhost & run`_
    2. To bruteforce the directory ⇒ `_use auxalari/scanner/http/brute_dirs & set rhost & run_`
    3. To explore the robots.txt ⇒ `_use auxalari/scanner/http/robots.txt & set rhost & run_`
    
      
    

> wget , dig ,whatweb ,lynx <url> ,

> **_`robots.txt`_**

  

  

  

### SQL

  

> if we found a MySql while we use nmap , we should see what the version of it and what the hosting of it

- if the hosting is ubuntu , try to login ⇒ _`mysql -h <ip> -u <username(defult in linux root>`_

> if u login in Mysql =⇒

1. if we login , we can see what the databases the server have ⇒ `**_show databases;_**`
2. when u see the databases , u can see in each one ⇒ **_`use <databases name>;`_**
3. then to see what info have ⇒ **_`select * from <table name> ;`_**
4. If we have access we can access any system file ⇒ `select load_file(”<any file in system>”);`

  

- _**U can use Metasploit =⇒**_

1. **_`use auxalry/scanner/mysql/mysql_writeable_dirs`_**
2. `setg rhost` ( to make it global variable for all session ) && `set dir_list /usr/share/wordlist/metas…/data/wordlist/directory.txt` && `set verbose false` && `set password “”` && `run`
3. `**_use auxalry/scanner/mysql/mysql_hashdump_**` ⇒ `set username <val username>` && `set password “”` && run
4. to scan for file ⇒ `**_use auxalry/scanner/mysql/mysql_file_enum && set rhost_**` && `**_set file_list /ust/share/meta…./data/wordlist/sensitive_file.txt_**` && `**_set password “”_**` && `**_run_**`
5. to bruteforce login ⇒ _`use auxalry/scanner/mysql/mysql_login`_ && _`set rhost`_ && _`set pass_file /usr/share/metasploit…./data/wordlist/unix_password.txt`_ && _`set username <username>`_ && _`set stop_on_success true`_

> For Windows Version

1. To bruteforce login ⇒ _`use auxalry/scanner/mssql/mssql_login`_ && _`set rhost <ip>`_ && _`set user_file <wordlist>`_ && _`set pass_file <wordlist>`_ && _`set verbose false`_ && _`run`_
2. To enum ⇒ `_use auxalry/admin/mssql/mssql_enum_` && _`set rhost <ip>`_ && _`set user_file <wordlist>`_ && _`set pass_file <wordlist>`_ && _`set verbose false`_ && _`run`_
3. To enum_login ⇒ `_use auxalry/admin/mssql/mssql_enum_sql_logins_` && _`set rhost <ip>`_ && _`set user_file <wordlist>`_ && _`set pass_file <wordlist>`_ && _`set verbose false`_ && _`run`_
4. To run command ⇒ `_use auxalry/admin/mssql/mssql_exec_` && _`set rhost <ip>`_ && `set cmd <command>` && _`set user_file <wordlist>`_ && _`set pass_file <wordlist>`_ && _`set verbose false`_ && _`run`_
5. To scan for domain account ⇒ `_use auxalry/admin/mssql/mssql_enum_domain_accounts_` && _`set rhost <ip>`_ && _`set user_file <wordlist>`_ && _`set pass_file <wordlist>`_ && _`set verbose false`_ && _`run`_

  

- we can use **_nmap_** to search for any users that’s dose not need password to login ⇒ `nmap <ip> -p 3306<port> -sV - -script=mysql(or ms-sql)-empty-password`
- If we want another info abot the database ⇒ `nmap <ip> -p 3306<port> -sV - -script=mysql-info`
- to scan the username ⇒ `nmap <ip> -p 3306<port> -sV - -script=mysql-users --script-args="mysqluser='<username>',mysqlpass='<password>'"`
- to list a databases ⇒ `nmap <ip> -p 3306<port> -sV - -script=mysql-databases --script-args="mysqluser='<username>',mysqlpass='<password>'"`
- to list variables ⇒ `nmap <ip> -p 3306<port> -sV - -script=mysql-variables --script-args="mysqluser='<username>',mysqlpass='<password>'"`
- to bruteforce login using nmap ⇒ _`nmap <ip> -p <port> - -script=ms-sql-brute - -script-args userdb=<wordlist>,passdb=<wordlist>`_
- try to run command ⇒ _`nmap <ip> -p <port> - -script=ms-sql-xp-cmdshell - -script-args mssql.username=<username>,mssql.password=<password>.ms-sql-xp-cmdshell.cmd=”<command>”`_

> ==**_type ⇒ like cat in linux_**==

  

  

- to bruteforce login =⇒ _`hydra -l <username> -p /usr/share/metasploit…./data/wordlist/unix_password.txt <ip> <protocol(mysql)>`_

  

> sql of windows version ⇒ ms-sql

- to scan for ms-sql info ⇒ _`nmap <ip> -p <protocol> - -script=ms-sql-info`_
- to advance scan by netbios ⇒ `_nmap <ip> -p <protocol> - -script=ms-sql-ntlm-info --script-args= mssql.instance-port=<port number>_`