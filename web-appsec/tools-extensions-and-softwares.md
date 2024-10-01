# Tools-Extensions-Bookmarks

## Tools&#x20;

* Burp Suite
  * [https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)
  * [https://portswigger.net/burp/pro/trial](https://portswigger.net/burp/pro/trial)&#x20;
* [https://github.com/0xAnuj/Blinks\
  ](https://github.com/0xAnuj/Blinks)  (Blinks is a powerful Burp Suite extension that automates active scanning with Burp Suite Pro and enhances its functionality.)
* [https://github.com/JesseClarkND/abnormalizer\
  ](https://github.com/JesseClarkND/abnormalizer) (IDN Homograph Attack)
* [https://0xacb.com/normalization\_table](https://0xacb.com/normalization\_table)  (IDN Homograph Attack)
* [https://lock.cmpxchg8b.com/rebinder.html\
  ](https://lock.cmpxchg8b.com/rebinder.html) (Test DNS Rebinding Attack)
* [https://github.com/robre/jsmon\
  ](https://github.com/robre/jsmon)  (javascript change monitoring tool for bugbounties)
* [https://github.com/ahussam/url-tracker](https://github.com/ahussam/url-tracker) (Change monitoring app that checks the content of web pages in different periods)
* [https://subdomainfinder.c99.nl/](https://subdomainfinder.c99.nl/)  (Online subdomain finder )
* [https://github.com/streaak/keyhacks](https://github.com/streaak/keyhacks) (For Expliitation of api keys and exposures)
* [https://www.irongeek.com/homoglyph-attack-generator.php](https://www.irongeek.com/homoglyph-attack-generator.php) (Homoglyph Attack Generator)
* [https://bbradar.io/](https://bbradar.io/)  (Radar for bug bounty programs)

## Extensions

* [https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/](https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/)
* [https://www.wappalyzer.com](https://www.wappalyzer.com/)
* [https://trufflesecurity.com/](https://trufflesecurity.com/)
* [https://github.com/yeswehack/yeswehack\_vdp\_finder](https://github.com/yeswehack/yeswehack\_vdp\_finder)
* [https://github.com/Authenticator-Extension/Authenticator](https://github.com/Authenticator-Extension/Authenticator)
* [https://addons.mozilla.org/en-US/firefox/addon/findsomething/](https://addons.mozilla.org/en-US/firefox/addon/findsomething/)
* [https://addons.mozilla.org/en-US/firefox/addon/hunterio/](https://addons.mozilla.org/en-US/firefox/addon/hunterio/)
* [https://addons.mozilla.org/en-US/firefox/addon/fake-filler/](https://addons.mozilla.org/en-US/firefox/addon/fake-filler/)
* [https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/](https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/)
* [https://addons.mozilla.org/en-US/firefox/addon/edge\_translate/](https://addons.mozilla.org/en-US/firefox/addon/edge\_translate/)
* [https://github.com/yeswehack/PwnFox\
  ](https://github.com/yeswehack/PwnFox)&#x20;
* [https://github.com/xnl-h4ck3r/XnlReveal](https://github.com/xnl-h4ck3r/XnlReveal)&#x20;
* [https://github.com/portswigger/methods-discloser\
  ](https://github.com/portswigger/methods-discloser)
* [https://github.com/kevin-mizu/domloggerpp](https://github.com/kevin-mizu/domloggerpp)

## Bookmarklets

> A bookmarklet is a [bookmark](https://en.wikipedia.org/wiki/Bookmark\_\(digital\)) stored in a [web browser](https://en.wikipedia.org/wiki/Web\_browser) that contains JavaScript commands that add new features to the browser. They are stored as the [URL](https://en.wikipedia.org/wiki/Uniform\_Resource\_Locator) of a bookmark in a [web browser](https://en.wikipedia.org/wiki/Web\_browser) or as a [hyperlink](https://en.wikipedia.org/wiki/Hyperlink) on a [web page](https://en.wikipedia.org/wiki/Web\_page). Bookmarklets are usually small snippets of [JavaScript](https://en.wikipedia.org/wiki/JavaScript) executed when user clicks on them. When clicked, bookmarklets can perform a wide variety of operations, such as running a search query from selected text or extracting data from a table.

* Getting paths from the source code and js files&#x20;

{% code overflow="wrap" %}
```javascript
javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\%60))/g;const%20results=new%20Set;for(var%20i=0;i<scripts.length;i++){var%20t=scripts[i].src;""!=t&&fetch(t).then(function(t){return%20t.text()}).then(function(t){var%20e=t.matchAll(regex);for(let%20r%20of%20e)results.add(r[0])}).catch(function(t){console.log("An%20error%20occurred:%20",t)})}var%20pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const%20match%20of%20matches)results.add(match[0]);function%20writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
```
{% endcode %}

* Getting urls from the source code of the page

{% code overflow="wrap" %}
```javascript
javascript:(function(){const decodeHTMLEntities=t=>{const e=document.createElement('textarea');return e.innerHTML=t,e.textContent};const urls=[...new Set([...document.documentElement.outerHTML.matchAll(/https?:\/\/[^\s"%'\>\<]+/g)].map(m=>decodeHTMLEntities(m[0])).filter(url=>/^https?:\/\/[^\s\/$.?#].[^\s]*$/.test(url)))];document.body.innerText=urls.join('\n')})();
```
{% endcode %}

* Getting urls from the all web archives resources (Don't forget add your API Key)

{% code overflow="wrap" %}
```javascript
javascript:(function(){var domain=prompt("Enter the domain:");if(domain){window.open("https://web.archive.org/cdx/search/cdx?url=*."+domain+"/*&output=text&fl=original&collapse=urlkey","_blank");window.open("https://www.virustotal.com/vtapi/v2/domain/report?apikey=<YOUR-API-Key>&domain="+domain,"_blank");setTimeout(function(){const decodeHTMLEntities=t=>{const e=document.createElement('textarea');return e.innerHTML=t,e.textContent};const urls=[...new Set([...document.documentElement.outerHTML.matchAll(/https?:\/\/[^\s"%'\>\<]+/g)].map(m=>decodeHTMLEntities(m[0])).filter(url=>/^https?:\/\/[^\s\/$.?#].[^\s]*$/.test(url)))];alert(urls.join('\n'));},5000);window.open("https://urlscan.io/api/v1/search/?q=domain:"+domain+"&size=10000","_blank");window.open("https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/url_list?limit=500","_blank");window.open("https://index.commoncrawl.org/CC-MAIN-2023-06-index?url=*."+domain+"/*&output=json&fl=timestamp,url,mime,status,digest","_blank");}})();
```
{% endcode %}

