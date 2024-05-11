# JavaScript Analysis

*   \[ ] JS Analysis Course

    [Javascript Analysis](https://www.youtube.com/playlist?list=PLcCG2wDOBXAWGn-\_ZAWUfvwu\_RkBtNxPt)
*   \[ ] JS Analysis for Pentesters

    [JavaScript Analysis for Pentesters](https://kpwn.de/2023/05/javascript-analysis-for-pentesters/)

***

*   \[ ] This OneLiner extracts all API endpoints from AngularJS & Angular JavaScript files

    ```bash
    curl -s URL |grep-Po "(\\)(?:[a-zA-Z\\-_\\:\\.0-9\\(\\]+))(V)*(?:[a-zA-Z\\-1:\\.0-9\\(\\]+))(\\)((?:[a-zA-Z\\-_\\1:1.0-9\\(\\+)" I sort -u
    ```
*   \[ ] Bookmark to extract all paths from js files

    ```jsx
    javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\\"|\\'|\\`))\\/[a-zA-Z0-9_?&=\\/\\-\\#\\.]*(?=(\\"|\\'|\\`))/g;const%20results=new%20Set;for(var%20i=0;i<scripts.length;i++){var%20t=scripts[i].src;""!=t&&fetch(t).then(function(t){return%20t.text()}).then(function(t){var%20e=t.matchAll(regex);for(let%20r%20of%20e)results.add(r[0])}).catch(function(t){console.log("An%20error%20occurred:%20",t)})}var%20pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const%20match%20of%20matches)results.add(match[0]);function%20writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
    ```
* Function Monitoring

```javascript
monitor(FUNCTION);

// If Function Sends Json Objects function hook
monitor(FUNCTION);
FUNCTION = function (ar ) {
    console.log("FUCNCTION called with arguments: " + JSON.stringify(ar));
}

// monitor Getter and Setter
monitor(location.__lookupGetter__("hash"));
monitor(location.__lookupSetter__("hash"));
debug(location.__lookupGetter__("hash"));
debug(location.__lookupSetter__("hash"));

// Find Function
$("").datepicker();
```

* BrekPoints on modifications

```
- Write click on the tag or attribute 
- select Break on
- Choose between options (attripute modification or asubtree modification)
```

