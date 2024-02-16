# Linux Commands

## Basic Linux Commands:

```bash
# Basic Linux Commands
tool --help              # Show Help Menu
man tool                # Show Manual of a command/tool
whatis tool             # Show one line manual of a tool
apropos <crack>         # Know the usage, not the tool
rm file                 # Remove file
rm -r Directory         # Remove Directory
mkdir                   # Make Directory
cp file                 # Copy file
cp -r directory         # Copy Directory
ifconfig                # Show IP configurations
ip a                    # Show IP
echo "Text"             # Show Text
nano file.txt           # Make and edit file
cat file.txt            # Show File Content In the Terminal
sudo adduser            # Add User
su - ahmed              # Switch to user Ahmed
passwd                  # Password Change
sudo updatedb           # Update Database
locate flag.txt         # Find File Location
find . -name flag.txt    # Find File Named Flag.txt in the current directory
history                 # Show all run commands
!<command_id>           # Run command from history
!!                      # Run the last command
CTRL+r                  # Do (reverse-i-search)`': to search for a command used earlier
sudo service <service_name> <command>     # Manage Service using service command
sudo systemctl <cmd> <service_name>       # Manage Service using systemctl command
sudo systemctl list-unit-files            # List unit files
sudo service <service_name> status        # Show the status of Services
apt update              # Update Kali installed tools and Database
apt upgrade             # Upgrade Kali installed tools
apt-cache search <tool>    # Search For a tool before install
apt show <tool>             # Show Tool Description before install
sudo apt install <tool>    # Install application
sudo apt remove <tool>     # Remove application
apt remove --purge <tool>  # Remove Configuration File
dpkg -i <APP>              # Install application Package
export H=h0tak88r         # Define variable for all sessions
h=h0tak88r               # Define variable for this session only
unset [VARIABLE_NAME]     # Unset variable
sudo nano ~/.bashrc       # Set permanent environment variables in .bashrc
export [VARIABLE_NAME]=[variable_value]  # Add this line to the .bashrc file
source ~/.bashrc          # Update the file source
echo "lol" > lol.txt       # Save word "lol" in a new file lol.txt
echo "lol" >> lol.txt      # Add to file data
cat < lol.txt              # Read from lol.txt as STDIN
ls -l > lol.txt 2> lol2.txt     # Save output in lol.txt and errors in lol2.txt
cat file.txt | tee lol    # Show output and save in lol
xargs                     # For arguments
ls | xargs rm             # Do ls and rm all files
grep "lol" lol.txt        # Search for word "lol" in file "lol.txt"
grep -i "lol" lol.txt      # Ignore case sensitivity
cat file.txt | grep "pass\\|password\\|admin"   # Grep multiple words
cat file.txt | grep [0-9]  # Grep range from 0 to 9
cat file.txt | grep ^lol   # Grep lines starting with word "lol"
cat file.txt | grep ^l.....m   # Grep lines starting with "l" and the 7th letter is "m"
cat file.txt | grep ^[a-f]     # Grep lines that start with any character in the range from "a" to "f"
alias l='ls -lah'        # Create aliases



# Stream Editor (sed)
sed                             # Stream Editor
sed 's/password/hacked/' lol.txt         # Edit the first word in each line matching "password" to "hacked"
sed 's/password/hacked/g' lol.txt        # Edit every word matching "password" to "hacked"

# File Manipulation
split -l 100 lol.txt new_        # Split every 100 lines into new files
head -n 100 rockyou.txt          # Show the first 100 lines of file "rockyou.txt"
tail -n 100 rockyou.txt          # Show the last 100 lines of file "rockyou.txt"
cut Emails-pass.txt | cut -d ":" -f 1   # Cut by ":" and print the first line before it
cat lol.txt | awk '{print $1,$3}'      # Show the 1st and 3rd columns of a file
cat lol.txt | awk '{if ($1~/Password/) print}'   # Print lines with the first column containing the word "Password"

# File Comparison and Manipulation
comm file1 file2                # Compare between 2 Files

# Background Processes and Job Control
sleep 1000&                     # Run process in the background
ps aux                          # Show active processes (similar to Task Manager in Windows)
jobs                            # Show running background commands
fg %1                            # Bring the process with ID 1 to the foreground
CTRL+Z                          # Stop the current process
bg %1                            # Restart the background process with ID 1
nohup <command>                 # Run the process even when you close the terminal and save output to nohup.txt
disown %1                       # Disown the process with ID 1
kill <id>                       # Kill a process

kill -9 <id>                    # Forcefully kill a process and close this session
# Package Management
inxi --disk                  # Check Disk Capacity
upower -i /org/freedesktop/UPower/devices/battery_BAT1   # Check Battery Details
sudo dpkg -i Xmind-for-Linux-amd64bit-23.09.11172-202310122350.deb   # Install Package
sudo dpkg -r xmind-vana     # Uninstall Package
sudo dpkg -l                 # List Installed Packages

# Send File to Discord using Webhook
cat results.txt | curl -X POST -F "file=@-" "https://discord.com/api/webhooks/your_webhook_url"

# Send File to Telegram using Webhook
cat results.txt | curl -X POST -F "document=@-" "https://api.telegram.org/bot<your_bot_token>/sendDocument" -F "chat_id=<your_chat_id>"

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

# Shell Navigation Shortcuts
CTRL-z                   # Sleep program
CTRL-a                   # Go to the start of the line
CTRL-e                   # Go to the end of the line
CTRL-u                   # Cut from the start of the line
CTRL-k                   # Cut to the end of the line
CTRL-r                   # Search history
!!                       # Repeat the last command
!abc                     # Run the last command starting with "abc"

# Environment Variables
env                      # Show environment variables
echo $NAME               # Output the value of $NAME variable
export NAME=value        # Set $NAME to a value
$PATH                    # Executable search path
$HOME                    # Home directory
$SHELL                   # Current shell

# I/O Redirection
cmd 2> file              # Redirect error output (stderr) of cmd to file
cmd 1>&2                 # Redirect stdout to the same place as stderr
cmd 2>&1                 # Redirect stderr to the same place as stdout
cmd &> file              # Redirect every output of cmd to file
cmd 2> /dev/null         # Redirect STDERR to /dev/null

# Process Monitoring
ps aux                   # Show active processes
watch <command>          # Watch the process or command output every 2 seconds

# History Management
export HISTIGNORE="&::ls:exit:clear:history"   # Ignore certain commands from history records
```
