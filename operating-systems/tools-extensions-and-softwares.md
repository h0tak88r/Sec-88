# Tools, Extensions and Softwares

* [https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)
* [https://portswigger.net/burp/pro/trial](https://portswigger.net/burp/pro/trial)&#x20;
* [https://github.com/xnl-h4ck3r/XnlReveal](https://github.com/xnl-h4ck3r/XnlReveal) (A Chrome/Firefox browser extension to show alerts for reflected query params, show Wayback archive links for the current path, show hidden elements and enable disabled elements)
* [https://github.com/0xAnuj/Blinks\
  ](https://github.com/0xAnuj/Blinks)  (Blinks is a powerful Burp Suite extension that automates active scanning with Burp Suite Pro and enhances its functionality.)
* [https://github.com/yeswehack/PwnFox\
  ](https://github.com/yeswehack/PwnFox)  (Test fpor Autherization Bugs)
* [https://github.com/JesseClarkND/abnormalizer\
  ](https://github.com/JesseClarkND/abnormalizer) (IDN Homograph Attack)
* [https://0xacb.com/normalization\_table](https://0xacb.com/normalization\_table)  (IDN Homograph Attack)
* [https://lock.cmpxchg8b.com/rebinder.html\
  ](https://lock.cmpxchg8b.com/rebinder.html) (Test DNS Rebinding Attack)
* [https://github.com/robre/jsmon\
  ](https://github.com/robre/jsmon)  (javascript change monitoring tool for bugbounties)
* [https://github.com/ahussam/url-tracker](https://github.com/ahussam/url-tracker) (Change monitoring app that checks the content of web pages in different periods)
* [https://github.com/portswigger/methods-discloser\
  ](https://github.com/portswigger/methods-discloser) (Check available methods for endpoint)
* [https://github.com/kevin-mizu/domloggerpp](https://github.com/kevin-mizu/domloggerpp) (A browser extension that allows you to monitor, intercept, and debug JavaScript sinks based on customizable configurations)
* Bookmark for getting paths from the source code and js files&#x20;

{% code overflow="wrap" %}
```javascript
javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\%60))/g;const%20results=new%20Set;for(var%20i=0;i<scripts.length;i++){var%20t=scripts[i].src;""!=t&&fetch(t).then(function(t){return%20t.text()}).then(function(t){var%20e=t.matchAll(regex);for(let%20r%20of%20e)results.add(r[0])}).catch(function(t){console.log("An%20error%20occurred:%20",t)})}var%20pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const%20match%20of%20matches)results.add(match[0]);function%20writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
```
{% endcode %}

* Bookmark for getting urls from the source code of the page

{% code overflow="wrap" %}
```javascript
javascript:(function(){const decodeHTMLEntities=t=>{const e=document.createElement('textarea');return e.innerHTML=t,e.textContent};const urls=[...new Set([...document.documentElement.outerHTML.matchAll(/https?:\/\/[^\s"%'\>\<]+/g)].map(m=>decodeHTMLEntities(m[0])).filter(url=>/^https?:\/\/[^\s\/$.?#].[^\s]*$/.test(url)))];document.body.innerText=urls.join('\n')})();
```
{% endcode %}

* Bookmark for getting urls from the wayback&#x20;

{% code overflow="wrap" %}
```javascript
javascript:(function(){var domain=prompt("Enter the domain:");if(domain){window.open("https://web.archive.org/cdx/search/cdx?url=*."+domain+"/*&output=text&fl=original&collapse=urlkey","_blank");}})();
```
{% endcode %}

* [https://subdomainfinder.c99.nl/](https://subdomainfinder.c99.nl/)  (Online subdomain finder )
* [https://github.com/streaak/keyhacks](https://github.com/streaak/keyhacks) (For Expliitation of api keys and exposures)
* [https://www.irongeek.com/homoglyph-attack-generator.php](https://www.irongeek.com/homoglyph-attack-generator.php) (Homoglyph Attack Generator)
* [https://bbradar.io/](https://bbradar.io/)  (Radar for bug bounty programs)
* [https://docs.google.com/document/d/1o-mpqcYApjuolQwDow6Z0Qx3tzeRrHcP5Y2t7t312rQ/edit?pli=1](https://docs.google.com/document/d/1o-mpqcYApjuolQwDow6Z0Qx3tzeRrHcP5Y2t7t312rQ/edit?pli=1)
* [https://www.wappalyzer.com/](https://www.wappalyzer.com/)
* [https://github.com/yeswehack/yeswehack\_vdp\_finder](https://github.com/yeswehack/yeswehack\_vdp\_finder)
* [https://github.com/Authenticator-Extension/Authenticator](https://github.com/Authenticator-Extension/Authenticator)
* [https://trufflesecurity.com/](https://trufflesecurity.com/)
* [https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/](https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/)
* [https://addons.mozilla.org/en-US/firefox/addon/findsomething/](https://addons.mozilla.org/en-US/firefox/addon/findsomething/)
* [https://addons.mozilla.org/en-US/firefox/addon/hunterio/](https://addons.mozilla.org/en-US/firefox/addon/hunterio/)
* [https://addons.mozilla.org/en-US/firefox/addon/fake-filler/](https://addons.mozilla.org/en-US/firefox/addon/fake-filler/)
* [https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/](https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/)
* [https://addons.mozilla.org/en-US/firefox/addon/edge\_translate/](https://addons.mozilla.org/en-US/firefox/addon/edge\_translate/)
