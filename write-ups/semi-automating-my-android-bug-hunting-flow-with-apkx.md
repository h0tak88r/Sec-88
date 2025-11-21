# Semi-Automating My Android Bug Hunting Flow with apkX

### The Problem: Repetitive Tasks in Bug Hunting

As a bug hunter working on multiple programs simultaneously, I found myself drowning in repetitive tasks. Every new Android target required the same tedious process:

1. **Getting the APK** - Multiple methods, multiple steps, and the complexity when it comes to region-restricted target (e.g Hulu is downloadable only in US) !
2. **Initial scanning** - Running traditional tools like MobSF is useless when it is not a fresh-program
3. **Manual manifest analysis** - Checking AndroidManifest.xml for vulnerable components can be time-consuming
4. **SSL pinning bypass** - Setting up Burp for API testing using frida and other techniques that takes alot of efforts and time

The cycle was exhausting and time-consuming. In an age where automation is king, I knew there had to be a better way.

### My Traditional Bug Hunting Methodology

#### 1. Getting the APK for the Target

This step alone was a pain point. Multiple methods, each with their own complexities:

**Method 1: Google Play Store (Real Device)**

```bash
# Install on real device
adb install target.apk

# Pull from device
adb pull /data/app/com.target.app/base.apk
```

**Method 2: APKPure & Alternative Stores**

* Download from APKPure, APKMirror, or other sources
* Often easier but may have different versions

**Method 3: Rooted Device Extraction**

```bash
# Find the APK
adb shell pm path com.target.app

# Pull the APK
adb pull /data/app/com.target.app/base.apk
```

#### 2. Fast Scan with Famous Tools

**Ostorlab** - Great for initial assessment

* Quick vulnerability detection
* Good for getting an overview

**MobSF** - Comprehensive analysis

* Static and dynamic analysis
* Detailed security reports

#### 3. Manual AndroidManifest.xml Analysis

This was the most time-consuming part. I had to manually check for:

* **Exported Activities** - `android:exported="true"`
* **Exported Services** - Potential for service hijacking
* **Broadcast Receivers** - Intent-based vulnerabilities
* **Content Providers** - Data exposure risks
* **WebViews** - XSS and injection possibilities
* **Deep Links** - URL scheme vulnerabilities
* **File Provider Exports** - File access vulnerabilities
* **Task Hijacking** - Activity hijacking via taskAffinity

#### 4. SSL Pinning Bypass & API Testing

* Use tools like **Frida** or **Objection** to bypass SSL pinning
* Set up **Burp Suite** for API interception
* Test endpoints for common vulnerabilities

***

### The Solution: apkX - A Custom Android Apps Security Scanner

{% embed url="https://github.com/h0tak88r/apkX" %}

I decided to build **apkX**, a comprehensive Android security analysis tool that automates my entire bug hunting workflow. What makes apkX special is its **regex-driven approach** - I can easily add new patterns and vulnerabilities as I discover them.

1. **Automated APK Acquisition:** apkX uses [apkeep](https://github.com/EFForg/apkeep) for downloading APK files from various sources

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

After Providing the Package Name and Initializing the scan you can download hte APK by one click&#x20;

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

1. **Static Regex Based Scanning:** Regex Based Secrets and vulnerability Scanning With Differrent Report Formats (HTML - Json) So you can integrate it with other tools easily

<figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

1. **Manifest Scanning and Export:** Regex Based Manifest Scan and One-Click Downloade Manifest if you still prefer manual approuch or if you wanna take a close look

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

1. **HTTPS Introspection:** apkX Uses [apk-mitm](https://github.com/niklashigi/apk-mitm) to automatically prepares Android APK files for HTTPS inspection

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>



***

### The Power of Regex-Driven Scanning

The beauty of apkX lies in its **configurable regex patterns**. When I discover a new vulnerability pattern, I simply add it to `regexes.yaml`:

```yaml
# Example: New vulnerability pattern
- name: CustomVulnerability
  regex: (vulnerablePattern|anotherPattern)
  confidence: high
```

This means:

* **Instant updates** - No need to wait for tool updates
* **Community sharing** - Share patterns with other researchers
* **Program-specific** - Customize for different bug bounty programs
* **Learning tool** - Understand vulnerability patterns through regex

***

### Conclusion

apkX has transformed my Android bug hunting workflow from a tedious, repetitive process into an efficient, automated system. By combining the power of regex-driven scanning with modern web interfaces, I can now:

* **Analyze more targets** in less time
* **Discover more vulnerabilities** with better coverage
* **Focus on exploitation** rather than discovery
* **Share knowledge** with the community

The age of manual, repetitive security testing is over. The future belongs to intelligent automation tools like apkX that adapt to new threats and scale with our needs.

**Ready to automate your Android bug hunting?** Check out apkX on GitHub and start building your own vulnerability patterns today.

### Quick Start Guide

```bash
# 1. Install apkX
git clone https://github.com/h0tak88r/apkX.git
cd apkX && go build -o bin/apkx cmd/apkx/main.go

# 2. Start web server
./bin/apkx-web -addr 127.0.0.1:9091

# 3. Open browser
open http://localhost:9091

# 4. Upload APK/PackageName and get instant results!
```
