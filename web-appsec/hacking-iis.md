# Hacking IIS

#### Resources

&#x20;https://youtu.be/XlmeSFm3RT4?si=hfhzGF9ymG6Igt5j&#x20;

https://www.youtube.com/watch?v=cqM-MdPkaWo&#x20;

https://www.youtube.com/watch?v=yyD8Z5Qar5I&#x20;

https://www.youtube.com/watch?v=02FrOIT8xPU&#x20;

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
