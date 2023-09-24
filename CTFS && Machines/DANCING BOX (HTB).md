[https://varnasse.co.uk/hack-the-box-3-dancing-write-up/](https://varnasse.co.uk/hack-the-box-3-dancing-write-up/)

## Introduction to Server Message Block (SMB)

We learned from the ‘Fawn’ box that we can use the File Transport Protocol to send files between two computers on separate networks. In this box, we are looking at the Server Message Block (SMB) – a protocol that allows us to transfer a file between two computers (hosts) on the same network. This communication protocol provides shared access to files, printers, and serial ports between endpoints on a network. We mostly see SMB services running on Windows machines.

SMB typically runs at the Application or Presentation layer of the OSI model and uses port 445/tcp. Therefore, due to this, it relies on lower-level protocols for transport. NetBIOS over TCP/IP is most often used with the Microsoft SMB Protocol and this is why, during our enumeration, we will most likely see both protocols with open ports running on the target machine.

An SMB-enabled storage on the network is called a _share_. These can be accessed by any client that has the same address of the server and the correct credentials. In order to function correctly within a network, SMB requires some security layers. At a user level, SMB clients are required to provide a username and password combination to interact with the contents of the SMB share.

However, as we will see, some system administrators make the mistake of using _guest accounts_ or _anonymous log-ons_. These may allow you to bypass this username/password security layer!

## Enumeration

As always, we begin by ensuring that our VPN connection is established and stable. To do so, we use the `ping` command to send and retreive packets from the `{Target_IP}`:

Running the ping command on our {Target_IP}

Great – we can see that our connection is established and stable. The `ping` command may not always work, especially in large-scale corporate environments, as firewall rules typically prevent ICMP packets to be sent between hosts. This is to avoid insdier threats and discover other hosts and services within the network.

Next, we want to scan the target to see what services are running. We use `nmap` along with the `-sV` tag to scan for version detection:

Using nmap with the -sV to see all services and their versions running on the host.

Our `nmap` scan shows three open ports: our SMB share is found on the `445/tcp` port meaning we can try and access this later.

In order to access a SMB share, we need to use a script called [_smbclient_](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). If it is not installed on your virtual machine, you can type the following command to install: `sudo apt-get install smbclient`

As I meantioned earlier, SMB shares have a security layer of a username and password authentication process. The _smbclient_ script will attempt to contact the share and checks for this authentication process. If there is, we will be prompted for the password for your local username. If we do not specify a username, then it will use our local machine’s username.

As always, I recommend reading the help options or manual for the script we are using. In this case, we can see the following capability of smbclient:

[-L|–list=HOST] : Selecting the targeted h`ost for the connection request.`

With this knowledge we can attempt to access the SMB share by typing the following command: `smbclient -L {Target_IP}`:

Connecting to the SMB share using the smbclient script.

When we run this command, we used our local username since we do not have any information about other usernames on the target and next we were prompted for a password. However, we are trying to get around this by trying to perform either a guest or anonymous authentication as any of these will result in us logging in without knowing a username/password combination.

When prompted for a password, we simply hit `Enter` and the script continues and as we can see in the above image, we have four separate shares displayed.

- `ADMIN$` – These are administrative shares that are hidden network shares to allow system administrators to have remote access for various purposes.
- `C$` – Administrative share for the `C:\` disk volume.
- `IPC$` – This is the inter-process communcation share.
- `WorkShares` – This is a custom share and one we might want to explore further.

## Gaining Access

Let us try and access these shares. We can start with `ADMIN$` and we will see if any of them have default configurations and allow us to bypass the password by simply pressing enter.

Attempting to access the `ADMIN$` share

Bummer – NT_STATUS_ACCESS_DENIED tells us we do not have the correct authentication. How about `C$`?

How about accessing the `C$` share?

Okay, still no luck. Well… maybe `WorkShares`?

Success – we’re in!

Success! We’re in. This share had a vulnerable username/password combination. As we can see the `smb: \>` prompt telling us our shell is interacting with the SMB service.

As usual, we can show the directories using the `ls` command:

Using the `ls` comman shows us two directories within the share.

We can use the `cd` command to change directory into each directory. Let’s see what is in Amy.J – we find a `worknotes.txt`

Moving into the Amy.J directory.

We can download the `worknotes.txt` file using the `get` command.

Let us move back and change directories into James.P. Listing the files and we find a `flag.txt`. We can download the file to the location where we ran our smbclient for future use.

We can kill the SMB shell and we can use the `cat` command to output the flag’s hash value.

Congratulations! We can now answer the tasks to pwn the box:

Tasks:

1. What does the 3-letter acronym SMB stand for? – **Server Message Block**
2. What port does SMB use to operate at? – **445**
3. What network communication model does SMB use, architecturally speaking? – **Client-Server Model**
4. What is the service name for port 445 that came up in our nmap scan? – **microsoft-ds**
5. What is the tool we use to connect to SMB shares from our Linux distribution? – **smbclient**
6. What is the `flag` or `switch` we can use with the SMB tool to `list` the contents of the share? – **L**
7. What is the name of the share we are able to access in the end? – **WorkShares**
8. What is the command we can use within the SMB shell to download the files we find? – **get**
9. Submit root flag – 5f61c10dffbc77a704d76016a22f1664