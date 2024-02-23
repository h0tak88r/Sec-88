# Linux File System

* _**/bin**_ (binaries): This directory contains Linux binaries like the cd and ls command that we executed earlier.
* _**/sbin**_ (system binaries): This directory holds system binary files that serve as administrative commands (like fdisk).
* _**/boot**_: This directory contains the Linux bootloader files.
* _**/dev**_ (devices): This directory contains the device configuration files (like _/dev/null_ ).
* _**/sys**_: This is similar to _/dev_, which contains configurations about devices and drivers.
* _**/etc**_ (etcetera): This directory contains all the administration system files (like _/etc/passwd_ shows all the system users in Kali Linux).
* _**/lib**_ (libraries): This directory hods the shared libraries for the binaries inside _/bin_ and _/sbin_.
* _**/proc**_ (processes): This directory contains the processes and kernel information files.
* _**/lost+found**_: As in the name, this directory contains the files that have been recovered.
* _**/mnt**_ (mount): This directory contains the mounted directories (example, a remote file share).
* _**/media**_: This directory holds the removable media mounted directories (like DVD).
* _**/opt**_ (option): This directory is used for add‐on software package installation. It is also used when installing software by users (example, hacking tools that you download from GitHub).
* _**/tmp**_ (temporary): This is a temporary folder used temporarily, the holdings are wiped after each reboot. The tmp folder is a good place to download our tools for privilege escalation once we got a limited shell.
* _**/usr**_ (user): This directory contains many sub-directories. In fact, _/usr/share/_ is a folder that we need to memorize because most of the tools that we use in Kali Linux (like Nmap, Metasploit, etc.) are stored there, and it also contains the wordlist dictionary files (_/usr/share/wordlists_).
* _**/home**_: This is the home for Kali Linux users (example _/home/kali/_).
* _**/root**_: Home directory for root user.
* _**/srv**_ (serve): This folder contains some data related to system server functionalities (like data for FTP servers).
* _**/var**_ (variable): This folder contains variable data for databases, logs, and websites. For an example, _/var/www/html/_ contains the files for the Apache2 web server.
* _**/run**_ (runtime): This directory holds runtime system data (like currently logged‐in users)
