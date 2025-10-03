# ASP.NET Security Testing

### Reference

{% embed url="https://docs.google.com/presentation/d/1q6gKVufrzPAJ7aZ5iOogCMVe6bOreC4v/edit?slide=id.p59#slide=id.p59" %}

### ASP Fuzzing

* Extensions.

```textile
Xml
Txt
Zip
7z 
Dll
Ashx
Asmx
Svc
HTML
HTM
JS
JSON
```

* Headers.

```http
Cookie: 
User-Agent: 
Accept: */*
```

* Example Findings

```
Api.zip
Wwwroot.zip
Bin.7z
Web.dll
Login.htm
Accesses.txt
appsettings.json
UploadHandler.ashx
File_Manager.asmx
Service1.svc
```

* Tools&#x20;
* FFUF

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://target.example/FUZZ -D -e .php,.html,.bak -t 40
```



* [**fuzzuli**](https://github.com/musana/fuzzuli)

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

```
go install -v github.com/musana/fuzzuli@latest

echo https://fuzzuli.musana.net fuzzuli -p
echo https://fuzzuli.musana.net|fuzzuli -mt shuffle
echo https://fuzzuli.musana.net|fuzzuli -mt regular
echo https://fuzzuli.musana.net|fuzzuli -mt withoutdots
echo https://fuzzuli.musana.net|fuzzuli -mt withoutvowels
echo https://fuzzuli.musana.net|fuzzuli -mt withoutdv
echo https://fuzzuli.musana.net|fuzzuli -mt reverse
echo https://fuzzuli.musana.net|fuzzuli -mt all
```

### Critical ASP Paths Often Overlooked by Pentesters.

```
/OBJ/Debug
intitle:"index of /obj“
APPname.dll, APPNAME.FUZZ.dll
Web.dll, WebConfig.txt, Web.xml
*.DLL
*.TXT
*.XML

/XML/
FUZZService.EXT|AppNameService.EXT|AppName.EXT
Login.asmx, admin.asmx, FileTransferService.svc
FUZZ /XML/ with XSL EXT
/xml/SupportAuth.xsl
*.XML
*.XSL
*.ZIP

/WebServices/
Config.xml, Export.zip, Login.XSL
SUPPORTTOKENINTERNAL on SupportAuth.aspx
*.ASMX
*.SVC
```

### Abusing ASP.NET\_SessionId for Unauthorized Access.

```bash
/Backup/ 403
Web.config
 <deny users="?" /> =anonymous  
UnAuth ASP.NET_SessionId=X
 <deny users="?" /> ≠ anonymous
 /backup/ 200
--------------------
/UsersInfo.ashx 302
if (Request.Cookies[".ASPXAUTH"] = null
UnAuth
.ASPXPath=X
if (Request.Cookies[".ASPXAUTH"] != null
/UsersInfo.ashx 200
---------------------
# Scenario
1. /Hdownload.ashx -> 302
2. /Login.aspx -> .ASPXPATH= (cookie parameter) 
3. /Hdownload.ashx  + .ASPXPATH= (cookie parameter) -> Bypassed
```

### Bypassing WAFs with ASP.NET Cookieless Sessions.

* Bypass WAF-Blocked Endpoints Using (S(x))

```bash
1. GET /admin/login.ASPX
2. The WAF only allows internal IPs to access the endpoint.
3. GET /admin/S(X))/login.ASPX --> 200 OK
```

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

### Uncovering Secrets in ASP.NET JS Files.

* Fuzzing For JS On ASP.NET

```
/
/js
/Javascript
/include
```

* Critical JavaScript Filenames On ASP.NET

```
appsettings.js
Config.js
debug.js
service-worker-assets.js
```

### Breaking Auth with Unique Path Manipulation.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>
