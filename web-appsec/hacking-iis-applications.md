# Hacking IIS Applications

### Resources

https://youtu.be/XlmeSFm3RT4?si=hfhzGF9ymG6Igt5j&#x20;

https://www.youtube.com/watch?v=cqM-MdPkaWo&#x20;

https://www.youtube.com/watch?v=yyD8Z5Qar5I&#x20;

https://www.youtube.com/watch?v=02FrOIT8xPU \


[https://www.youtube.com/watch?v=\_4W0WXUatiw](https://www.youtube.com/watch?v=\_4W0WXUatiw)\


{% embed url="https://x.com/infosec_au/status/1340785029899698181" %}

{% embed url="https://soroush.me/blog/" %}

{% embed url="https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/" %}

{% embed url="https://retkoussa.medium.com/microsoft-iis-server-shortnames-tilde-magic-64df65d26450" %}

## HTTPAPI 2.0 Assets <a href="#id-7ce1" id="id-7ce1"></a>

* Got HTTPAPI ERROR 404&#x20;
* It is IP but you can get the subdomain from the certificate common name
*   Edit the Host Header&#x20;

    <figure><img src="../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

### VHost Hopping <a href="#id-7ce1" id="id-7ce1"></a>

* Came across subdomain that running IIS Server apply.company.com
* VHost Enumeration using ffuf or burp intruder
* Found mssql.company.com
* Running MSSQL Explorer/Manager

### Local FIle Disclosure to DLLs

* DownloadCategoryExcel?fileName=../../web.config
* DownloadCategoryExcel?fileName=../../glopal.asax
* \<add namespace="Company.Web.Api.dell/>
* DownloadCategoryExcel?fileName=../../bin/Company.Web.Api.dll

### LFD -> RCE

* [https://bit.ly/2MzJ1qI](https://bit.ly/2MzJ1qI)
* Optain machinekey from web.config file (validation key and decryption keyy)
* VIEWSTATE -> Insecure Deserialization -> RCE&#x20;
* [https://github.com/0xacb/viewgen](https://github.com/0xacb/viewgen)

### RCE with Local&#x20;

{% embed url="https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/" %}

### ASP.NET XSS

* Try in login pages, redirects, forms & dynamic URL construction (\~/images/). Payload: `/(A(%22onerror='alert%60123%60'test))/`

{% embed url="https://x.com/nav1n0x/status/1799384973407031565" %}

### DNSpy

* Found Leaked zip files contains DLL Files?
* [https://github.com/dnSpy/dnSpy](https://github.com/dnSpy/dnSpy)
* Use DNSpy to reverse them to source code
* or [https://www.jetbrains.com/decompiler/](https://www.jetbrains.com/decompiler/)

### Partial Fuzzing&#x20;

* `shortscan https://apply.company.com/`&#x20;
* Got a part of file names not the full name ? let's fuzz the rest
* LIDSDI -> LIDFUZZ | EASYFI -> EASYFUZZ
* `ffuf -w wordlist.txt -D -e asp,aspx,ashx,asmx -t 100 -c -u https://apply.company.com/lidsFUZZ`
* You can make your own wro=dlist using wordlist generator\
  [https://sourceforge.net/projects/crunch-wordlist/](https://sourceforge.net/projects/crunch-wordlist/)\
  [https://github.com/jim3ma/crunch](https://github.com/jim3ma/crunch)
* `./crunch 0 3 abcdefghijklmnopqrstuvwxyz0123456789 -o 3char.txt`
* Fuzzing doesn't work? try search in Github or use [https://github.com/retkoussa/gsnw](https://github.com/retkoussa/gsnw/tree/main)

## Nuclei <a href="#id-7ce1" id="id-7ce1"></a>

Check out the [Nuclei templates](https://github.com/projectdiscovery/nucleitemplates/blob/d6636f9169920d3ccefc692bc1a6136e2deb9205/fuzzing/iis-shortname.yaml) for fuzzing techniques.

## Fingerprinting with Shodan <a href="#id-5c3c" id="id-5c3c"></a>

Utilize Shodan to identify IIS instances with specific characteristics:

* `http.title:"IIS"`
* `Ssl:"Company Inc." http.title:"IIS"`
* `Ssl.cert.subject.CN:"company.in" http.title:"IIS"`

## Fingerprinting Techniques <a href="#c848" id="c848"></a>

### Cookies <a href="#e074" id="e074"></a>

* `ASP.NET_Sessionid`
* `ASPSESSION`

### Headers Regex <a href="#dcb3" id="dcb3"></a>

* `X-AspNet-Version: (.*)\\;version:\\1`
* `X-Powered-By:^ASP\\.NET`

### HTML Regex <a href="#id-8078" id="id-8078"></a>

* `<input[^>]+name\"_VIEWSTATE`

### URL Regex <a href="#id-26e5" id="id-26e5"></a>

* `\\.aspx?(?.$|\\?)`

## Ignoring Directories from Scanning <a href="#id-2052" id="id-2052"></a>

Exclude these directories from your scans:

* `ASPNET~1`
* `DEFAULT~1.ASP`
* `DEFAULT~1.CSS`
* `GLOBAL.ASA`
* `GLOBAL.ASP`
* `GLOBAL.CS`
* `MASTER.CS`
* `WEB.CON`

## Extensions to Bruteforce <a href="#id-2c13" id="id-2c13"></a>

Bruteforce file extensions to uncover vulnerabilities:

* `.aspx` (Legacy active server pages)
* `.aspx` (Modern Active server pages)
* `.ashx` (APIs/AJAX)
* `.wsdl` (Web Services Description Language)
* `.wadl` (Web Application Description Languages)
* `.asmx` (XML Web Services)
* `.xml`
* `.zip`
* `.txt`

## Tools for Investigation <a href="#b935" id="b935"></a>

**Burp Extension:** [IIS Tilde Enumeration Scanner](https://portswigger.net/bappstore/523ae48da61745aaa520ef689e75033b)

**Shortscan Tool**

* `shortscan` [`https://example.com/`](https://example.com/)
* `shortscan` [`https://example.com/admin/`](https://example.com/admin/)
* `shortscan` [`https://example.com/test`](https://example.com/test)

**ffuf**

* `ffuf -w iis.txt -u` [`https://example.com/FUZZ`](https://example.com/FUZZ)
* `ffuf -w iis.txt -u` [`https://example.com/shortnameFUZZ`](https://example.com/shortnameFUZZ)

**IIS Short Name Scanner**

* Explore the latest version on [GitHub](https://github.com/irsdl/IIS-ShortName-Scanner).

**nmap**

* `nmap -p80 --script http-iis-short-name-brute 71.167.30.116`

**sns**

* Discover the tool at [https://github.com/se33tLie/sns](https://github.com/se33tLie/sns).
