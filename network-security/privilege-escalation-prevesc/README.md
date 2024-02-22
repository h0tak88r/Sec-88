# Privilege Escalation \[PrevEsc]

### Privilege Escalation

### Manual Enumeration

**Users**

* **Windows:**
  *   Identify the current user:

      ```bash
      whoami
      net user
      ```
* **Linux:**
  *   Identify the current user and user details:

      ```bash
      whoami
      id
      ```

**Hostname**

* **Windows:**
  *   Obtain system and hostname information:

      ```bash
      systeminfo
      hostname
      ```
* **Linux:**
  *   Obtain system and hostname information:

      ```bash
      uname -a
      hostname
      cat /etc/issue
      ```

**Running Processes and Services**

* **Windows:**
  *   List running processes and associated services:

      ```bash
      tasklist /svc
      ```
* **Linux:**
  *   List all running processes:

      ```bash
      ps aux
      ```

**Network Information**

* **Windows:**
  *   Obtain network information:

      ```bash
      ipconfig /all
      route print
      netstat -ano
      ```
* **Linux:**
  *   Obtain network information:

      ```bash
      ip a | sudo ifconfig
      ssh -anp
      ```

**Firewall**

* **Windows:**
  *   Check Windows firewall settings:

      ```bash
      netsh advfirewall show currentprofile
      netsh advfirewall firewall show rule name=all
      ```
* **Linux:**
  *   Check iptables rules:

      ```bash
      iptables -L
      ```

**Scheduled Tasks**

* **Windows:**
  *   List scheduled tasks:

      ```bash
      schtasks /query /fo LIST /v
      ```
* **Linux:**
  *   List scheduled tasks:

      ```bash
      ls -lah /etc/cron*
      ```

**Applications and Patch Levels**

* **Windows:**
  *   List installed applications and patches:

      ```bash
      wmic product get name, version, vendor
      wmic qfe get Caption, Description, HotFixID, InstalledOn
      ```
* **Linux:**
  *   List installed packages:

      ```bash
      dpkg -l
      ```

**Readable/Writable Files**

* **Windows:**
  *   Check permissions of files and directories:

      ```bash
      accesschk.exe -uws "Everyone" "C:/Program Files"
      ```
* **Linux:**
  *   Find writable directories:

      ```bash
      find / -writable -type d 2>/dev/null
      ```

**Unmounted Disks**

* **Windows:**
  *   List unmounted disks:

      ```bash
      mountvol
      ```
* **Linux:**
  *   List unmounted disks:

      ```bash
      mount
      ```

**Drivers and Kernel Modules**

* **Windows:**
  *   List installed drivers:

      ```bash
      driverquery.exe
      ```
* **Linux:**
  *   List loaded kernel modules:

      ```bash
      lsmod
      modinfo <MODULE_NAME>
      ```

**Binaries that Auto Elevate**

* Identify binaries that auto elevate privileges.

### Automated Enumeration

**Tools**

* Use various tools for automated privilege escalation enumeration:
  * Windows:
    * windows-privesc-checker
    * Watson
    * Sherlock
    * PowerUp
    * Windows-Exploit-Suggester
    * JAWS
    * WinPEAS.exe and .bat
  * Linux:
    * linPEAS
    * LinEnum

#### Windows PrivEsc

**Insecure File Permissions**

* **Using PowerShell:**
  *   Set execution policy and use PowerUp tool:

      ```powershell
      Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
      Import-Module .\PowerUp.ps1
      Invoke-AllChecks
      ```
  *   Check file permissions:

      ```powershell
      icacls.exe "<FILE_PATH>"
      ```

**Unquoted Service Paths**

* Create a malicious .exe file in one of the unquoted paths.

#### Linux PrivEsc

**Understanding Permissions in Linux**

* Learn about file and directory permissions in Linux.

**sudo -l**

*   Check sudo privileges:

    ```bash
    sudo -l
    ```

**sudo vim -c ':!/bin/bash'**

*   Escalate privileges using Vim:

    ```bash
    sudo vim -c ':!/bin/bash'
    ```
