---
description: API2-Broken Authentication
---

# Broken Authentication

### Authentication Bypass: Password Brute-Force Attacks and Password Spraying

#### Password Brute-Force Attacks:

**Tools and Wordlists:**

* **Mentalist App:** (https://github.com/sc0tfree/mentalist)
* **Common User Passwords Profiler (CUPP):** (https://github.com/Mebus/cupp)
* **Wordlist:** An example of a popular wordlist is `rockyou.txt`. It's often available on Kali Linux and can be unzipped using `gzip -d /usr/share/wordlists/rockyou.txt.gz`.

**Performing a Brute-Force Attack with Wfuzz:**

1. **Preparation:**
   * Unzip the wordlist (`rockyou.txt`) if needed.
2. **Using Wfuzz:**
   *   Check the Wfuzz help menu to understand available options:

       ```bash
       wfuzz --help
       ```
   * Important options for API testing include:
     * Headers option (`-H`)
     * Hide responses options (`--hc`, `--hl`, `--hw`, `--hh`)
     * POST body requests (`-d`)
3. **Crafting the Wfuzz Attack:**
   * Specify the content-type headers for the API (e.g., `Content-Type: application/json` for crAPI).
   *   Define the POST body for the login endpoint, where `FUZZ` is the attack position:

       ```bash
       wfuzz -d '{"email":"a@email.com","password":"FUZZ"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/rockyou.txt -u http://127.0.0.1:8888/identity/api/auth/login --hc 405
       ```
   * In this example, the attack checks for valid passwords against the login endpoint, and irrelevant responses (status code 405) are hidden.
4. **Reviewing Results:**
   * Analyze the results, looking for valid passwords. Successful attempts will show responses with a 200 status code.

#### Password Spraying:

**Password Spraying Strategies:**

1. **Simple Passwords:**
   * Use easily guessable passwords that meet basic requirements (e.g., `QWER!@#$`, `Password1!`).
2. **Target-Related Passwords:**
   * Create passwords related to the target, including a capitalized letter, a number, details about the organization, and a symbol.
   *   Example password-spraying list for Twitter employees:

       ```
       Summer2022!
       Spring2022!
       QWER!@#
       March212006!
       July152006!
       Twitter@2022
       JPD1976!
       Dorsey@2022
       ```

**Maximizing User List:**

* The key to password spraying is to maximize the user list, increasing the chances of compromising a user account with a weak password.
* Build a user list during reconnaissance or by exploiting vulnerabilities like excessive data exposure.

**Note on Base64 Encoding:**

* Some APIs may base64-encode authentication payloads.
* If an API encodes to base64, adjust fuzzing attacks to include base64 payloads using tools like Burp Suite Intruder, which can encode and decode base64 values.
* Base64 encoding does not enhance security and is often done for encoding comparison on the backend.
