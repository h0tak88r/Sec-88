---
description: >-
  If you enjoy what I do, please support me  Buy Me Ko-fi!
  https://ko-fi.com/h0tak88r
---

# 📱 Android-AppSec

{% embed url="https://github.com/Ralireza/Android-Security-Teryaagh/blob/main/00-Roadmap/Android-Security-Roadmap.pdf" %}

{% embed url="https://app.hextree.io/map" %}

1. Learned Web Pentesting&#x20;
2. Learned JAVA basics and OOP
   1. [Lazy Programmers](https://www.youtube.com/playlist?list=PLjTzpE6cvFak0CToStX3aHn6nXPdQz6d0) -> Arabic Course
   2. [OOP (omarAhmed)](https://www.youtube.com/playlist?list=PLwWuxCLlF_ue7GPvoG_Ko1x43tZw5cz9v) -> Arabic Course&#x20;
3. Learned Android App Development
   1. [lazyProgrammers](https://youtube.com/playlist?list=PLjTzpE6cvFakLb80cpN-9vUcGgL_BbOPI\&si=Q3utrn2QFqry8_GI) -> Arabic Course ( i was focusing on java so i didn't study kotlin part)
   2. [Android App Java Tutorials](https://youtube.com/playlist?list=PLnzqK5HvcpwR8Y_aYk3mS3vPv52c0LC5K\&si=O_GXBa1po0GdBo2p) -> Arabic Course
   3. [freeCodeCamp](https://youtu.be/fis26HvvDII?si=cNr9AkscRwjciNkf) -> English Course
4. Learned Android App Pentesting basics
   1. [Android Application Pen-testing Course](https://youtube.com/playlist?list=PL4S940IsHJYWhhYOpBk6Y-U9nTQq2omae\&si=VX69LE_9awscH2il) -> Arabic Course
5. Dive in Android App Hacking World
   1. [Guide to Android Application Bug Bounty](https://www.udemy.com/course/the-complete-guide-to-android-bug-bounty-penetration-tests/)
   2. [Android App Hacking - Black Belt Edition](https://www.udemy.com/course/android-app-hacking-black-belt-edition/)&#x20;
   3. [Hack-Tricks](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting)&#x20;
   4. [Frida for Beginners](https://www.udemy.com/course/frida-for-beginners)
   5. [overSecuredBlog](https://blog.oversecured.com/)
   6. [elcapitano-blog](https://mohamed-ashraf.notion.site/Mobile-pentest-df8295a9922a44e7aa171a598a820db4)

### Android Security Awesome

This section contains materials on the security of Android applications, including various articles, studies, analysis tools and useful libraries to ensure the security of applications.&#x20;

#### Analysis Tools

This block is broken into several parts. First, you can see common solutions for analyzing and searching for vulnerabilities. Some of them intersect with tools for iOS, because among them there are universal frameworks (but few of them).

Then there are tools used for dynamic analysis (it is necessary to run the application on a real device or emulator).&#x20;

Well, the last point - the tools available online, using which you can download the application file and get the result after a while.

**General**

<details>

<summary>References</summary>

* [Pithus](https://beta.pithus.org/) [(github)](https://github.com/Pithus/bazaar) - free and open-source platform to Android analysis applications
* [CuckooDroid 2.0 - Automated Android Malware Analysis](https://github.com/idanr1986/cuckoodroid-2.0)
* [QARK - An Obfuscation-Neglect Android Malware Scorping System](https://github.com/quark-engine/quark-engine)
* [QARK – Quick Android Review Kit](https://github.com/linkedin/qark)
* [ProxyDroid](https://play.google.com/store/apps/details?id=org.proxydroid\&hl=ru)
* [ADB Toolkit](https://github.com/ASHWIN990/ADB-Toolkit)
* [InjectFake SecurityProvider](https://github.com/darvincisec/InjectFakeSecurityProvider) - print the key, key key key, algorithm parameters, keystore password in logcat
* [MEDUSA](https://github.com/Ch0pin/medusa)
* [diffuse](https://github.com/JakeWharton/diffuse)
* [ApkDiff](https://github.com/daniellockyer/apkdiff)
* [GDA(GJoy Dex Analyzer)](https://github.com/charles2gan/GDA-android-reversing-Tool)
* [APKProxyHelper](https://github.com/evilpenguin/APKProxyHelper)
* [APKLab](https://github.com/APKLab/APKLab)
* [RASE - Persistent Rooting Android Studio Emulator](https://github.com/m2sup3rn0va/RASEv1)
* [EdXposed Framework](https://github.com/ElderDrivers/EdXposed)
* [fridroid-unpacker](https://github.com/enovella/fridroid-unpacker) - Defeat Java packers via Frida instrumentation
* [CheckKarlMarx](https://github.com/devkekops/checkkarlmarx) - Security checks for release assemblies
* [parserDex](https://github.com/windy-purple/parserDex/blob/master/%E5%AD%97%E7%AC%A6%E4%B8%B2%E8%A7%A3%E6%9E%90/parserDexStrings.py)
* [Androguard](https://github.com/androguard/androguard)
* [Amandroid – A Static Analysis Framework](http://pag.arguslab.org/argus-saf)
* [Androwarn – Yet Another Static Code Analyzer](https://github.com/maaaaz/androwarn/)
* [APK Analyzer – Static and Virtual Analysis Tool](https://github.com/sonyxperiadev/ApkAnalyser)
* [APK Inspector – A Powerful GUI Tool](https://github.com/honeynet/apkinspector/)
* [Droid Hunter – Android application vulnerability analysis and Android pentest tool](https://github.com/hahwul/droid-hunter)
* [Error Prone – Static Analysis Tool](https://github.com/google/error-prone)
* [Findbugs – Find Bugs in Java Programs](http://findbugs.sourceforge.net/downloads.html)
* [Find Security Bugs – A SpotBugs plugin for security audits of Java web applications.](https://github.com/find-sec-bugs/find-sec-bugs/)
* [Flow Droid – Static Data Flow Tracker](https://github.com/secure-software-engineering/FlowDroid)
* [Smail/Baksmail – Assembler/Disassembler for the dex format](https://github.com/JesusFreke/smali)
* [Smail-CFGs – Smail Control Flow Graph’s](https://github.com/EugenioDelfa/Smali-CFGs)
* [SPARTA – Static Program Analysis for Reliable Trusted Apps](https://www.cs.washington.edu/sparta)
* [Thresher – To check he reachability properties](https://plv.colorado.edu/projects/thresher/)
* [Vector Attack Scanner – To Search Points to Volilial Attack](https://github.com/Sukelluskello/VectorAttackScanner)
* [Gradle Static Analysis Plugin](https://github.com/novoda/gradle-static-analysis-plugin)
* [Android Check – Static Code Analysis Slyn for Android Project](https://github.com/noveogroup/android-check)
* [APK Leaks – Scanning APK file for URIS, endpoints & secrets](https://github.com/dwisiswant0/apkleaks)
* [fridax](https://github.com/NorthwaveSecurity/fridax)
* [MOBEXLER](https://mobexler.com/)
* [Generate Malformed QRCodes](https://github.com/h0nus/QRGen)
* [Tool for Injecting Malicious Payloads Into Barcodes](https://github.com/huntergregal/scansploit)
* [AFL - american fuzzy lop](https://lcamtuf.coredump.cx/afl/)
* [Setup for i0S and Android Application Analysis](https://m2sup3rn0va.github.io/SiAAA/) - This is a cheatsheet to install tools required for i0S and Android application pentesting
* [AES Killer (Burpsuite Plugin)](https://github.com/Ebryx/AES-Killer)
* [ReFlutter](https://github.com/ptswarm/reFlutter)
* [Lief](https://github.com/lief-project/LIEF)
* [Mobile Verification Toolkit](https://github.com/mvt-project/mvt)

</details>

**Dynamic analysis**

<details>

<summary>References</summary>

* [Stingray](https://stingray-mobile.ru/)
* [Adhritis - Android Security Suite for in-depth reconnaissance and static bytecode analysis based on Ghera benchmarks](https://github.com/abhi-r3v0/Adhrit)
* [Android Hooker - Opensource project for Dynamic Analysiss of Android Applications](https://github.com/AndroidHooker/hooker)
* [AppAudit - Online tool (including an API) use dynamic and static analysis](http://appaudit.io/)
* [AppAduct - A bare-metal analysis tool on Android devices](https://github.com/ucsb-seclab/baredroid)
* [DroidBox - Dynamic Analysis of Android Applications](https://github.com/pjlantz/droidbox)
* [Droid-FF - Android File Fuzzing Framework](https://github.com/antojoseph/droid-ff)
* [Drozer](https://labs.f-secure.com/tools/drozer/)
* [Marvin - Analyses Android applications and allow tracking of an app](https://github.com/programa-stic/marvin-django)
* [Inspeckage](https://github.com/ac-pm/Inspeckage)
* [PATDroid - Collection of tools and data structures for Android applications](https://github.com/mingyuan-xia/PATDroid)
* [AndroL4b - Android security virtual machine on ubuntu-mate](https://github.com/sh4hin/Androl4b)
* [Radare2 - Unix-like reverse engineering framework and commandline tools](https://github.com/radareorg/radare2)
* [Cutter - Free and Open Source RE Platform Powered by Darree2](https://cutter.re/)
* [ByteCodeViewer - Android APK Reverse Engineering Suite (Decomiler, Editor, Debugger)](https://bytecodeviewer.com/)
* [Mobile-Security-Framework MobS](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Runtime Mobile Security (RMS) - is a powerful web interface that helps you manipulate to Android and iOS Apps at Runtime](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)

</details>

**Online analyzers**

<details>

<summary>References</summary>

* [Android APK Decompiler](http://www.decompileandroid.com/)
* [Ostor Lab](https://www.ostorlab.co/scan/mobile/)
* [Quixxi](https://quixxisecurity.com/)
* [Visual Threat](http://www.visualthreat.com/UIupload.action)

</details>

#### Vulnerable Applications

Various vulnerable applications that can be trained in analysis and see what security problems are at all.

<details>

<summary>References</summary>

* [Allsafe](https://github.com/t0thkr1s/allsafe)
* [InsecureShop](https://github.com/hax0rgb/InsecureShop)
* [OWASP: OMTG-Hacking-Playground](https://github.com/OWASP/OMTG-Hacking-Playground)
* [Daman insecure and App (DIVA)](http://payatu.com/damn-insecure-and-vulnerable-app/)
* [Damn-Vulnerable-Bank](https://github.com/rewanth1997/Damn-Vulnerable-Bank)
* [InjuredAndroid](https://github.com/B3nac/InjuredAndroid)
* [Damn Vulnerable Hybrid Mobile App (DVHMA)](https://github.com/logicalhacking/DVHMA)
* [ExploitMe labs by SecurityCompass](http://securitycompass.github.io/AndroidLabs/setup.html)
* [InsecureBankV2](https://github.com/dineshshetty/Android-InsecureBankv2)
* [Sieve (Vulnerable ‘Password Manager’ app)](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk)
* [sievePWN](https://github.com/tanprathan/sievePWN)
* [Android Labs](https://github.com/SecurityCompass/AndroidLabs)
* [Digitalbank](https://github.com/CyberScions/Digitalbank)
* [Dodo Voluline Bank](https://github.com/CSPF-Founder/DodoVulnerableBank)
* [Oracle android app](https://github.com/dan7800/VulnerableAndroidAppOracle)
* [Urdu vulnerability app](http://urdusecurity.blogspot.co.ke/2014/08/Exploiting-debuggable-android-apps.html)
* [MOshZuk](http://imthezuk.blogspot.co.ke/2011/07/creating-vulnerable-android-application.html?m=1) [File](https://dl.dropboxusercontent.com/u/37776965/Work/MoshZuk.apk)
* [Appknox](https://github.com/appknox/vulnerable-application)
* [Vuln app](https://github.com/Lance0312/VulnApp)
* [Daman Vulnerable FirefoxOS Application](https://github.com/arroway/dvfa)
* [Android Security Sandbox](https://github.com/rafaeltoledo/android-security)
* [OVAA (Oversecured Vulnerable Android App)](https://github.com/oversecured/ovaa)
* [SecurityShepherd](https://github.com/OWASP/SecurityShepherd)
* [OWASP-mstg](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)
* [Purpose very Insecure and Vulnerable Android Application (PIIVA)](https://github.com/htbridge/pivaa)
* [Sieve app](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk)
* [Vulnerable Android Application](https://github.com/Lance0312/VulnApp)
* [Android - Security](https://github.com/rafaeltoledo/android-security)
* [VulnDroid](https://github.com/shahenshah99/VulnDroid)
* [FridaLab](https://rossmarks.uk/blog/fridalab/)
* [Santoku Linux - Mobile Security VM](https://santoku-linux.com/)
* [Vuldroid](https://github.com/jaiswalakshansh/Vuldroid)
* [DamanVulnerableCryptoApp](https://github.com/DamnVulnerableCryptoApp/DamnVulnerableCryptoApp/)

</details>

#### Articles

This is the largest section of all. Here are articles on various topics related to Android security. Separately collected all Russian-language materials, as well as articles using Frida.

**Ru**

<details>

<summary>References</summary>

* [Development of Android security mechanisms (from version to version)](https://habr.com/ru/company/swordfish_security/blog/565092/)
* [Security of mobile OAuth 2.0](https://habr.com/ru/company/vk/blog/417031/)
* [Android Task Hijacking. We analyze the actual technique of replacing applications in Android](https://xakep.ru/2017/08/14/android-task-hijacking/)
* [Checked with PVS-Studio Android source codes, or no one is perfect](https://habr.com/ru/company/pvs-studio/blog/418891/)
* [Replace Runtime Permissions in Android](https://medium.com/mobileup/%D0%BF%D0%BE%D0%B4%D0%BC%D0%B5%D0%BD%D1%8F%D0%B5%D0%BC-runtime-permissions-%D0%B2-android-17c58bad954f)
* [How root rights and alternative firmware make your Android smartphone vulnerable](https://habr.com/ru/post/541190/)
* [Drozer, emulator and elven crutches](https://telegra.ph/Drozer-ehmulyator-i-ehlfijskie-kostyli-08-20)

</details>

**En**

<details>

<summary>References</summary>

**Frida**

* [Tiktok data acquisition Frida tutorial, Frida Java Hook detailed explanation: code and example. Part 1](https://www.fatalerrors.org/a/code-and-example.html)
* [Tiktok data acquisition Frida tutorial, Frida Java Hook detailed explanation: code and example. Part 2](https://www.fatalerrors.org/a/0d901j8.html)
* [Frida. 11x256's Reverse Engineering blog](https://11x256.github.io/)
* [Blog about Frida. grepharder blog](https://grepharder.github.io/blog/)
* [Frida Scripting Guide](https://neo-geo2.gitbook.io/adventures-on-security/)
* [Android Hacking with FRIDA](https://joshspicer.com/android-frida-1)
* [How to Direct Android Native Terms with Frida (Noob Friendly)](https://erev0s.com/blog/how-hook-android-native-methods-frida-noob-friendly/)
* [Frida scripting guide for Java](https://neo-geo2.gitbook.io/adventures-on-security/frida-scripting-guide/frida-scripting-guide)
* [Reverse Engineering Nike Run Club Android App Used Frida](https://yasoob.me/posts/reverse-engineering-nike-run-club-using-frida-android/)
* [Penttesting Android Apps Using Frida](https://www.notsosecure.com/pentesting-android-apps-using-frida/)
* [Android Root Detection Bypass Using Objection and Frida Scripts](https://medium.com/@GowthamR1/android-root-detection-bypass-using-objection-and-frida-scripts-d681d30659a7)
* [Mobile Pentesting With Frida](https://drive.google.com/file/d/1JccmMLi6YTnyRrp_rk6vzKrUX3oXK_Yw/view)
* [How to use FRIDa to bruteforce Secure Startup with FDE-encryption on a Samsung G935F Android running 8](https://github.com/Magpol/fridafde)
* [Decrypting Mobile App using AES Killer and Frida](https://n00b.sh/posts/aes-killer-mobile-app-demo/)
* [How Learning to Use Frida with Unity App](https://github.com/kylesmile1103/Learn-Frida)
* [Beginning Frida: Learning Frida use on Linux and (just a bit on) Wintel and Android systems with Python and JavaScript (Frida. hooking, and other tools)](https://www.amazon.com/Beginning-Frida-Learning-Android-JavaScript/dp/B094ZQ1HHC)

**Others**

* [Selection of dyscalos with HackerOne](https://threader.app/thread/1129680329994907648)
* [Detailed instructions for setting up the working environment](https://blog.cobalt.io/getting-started-with-android-application-security-6f20b76d795b)
* [Android Security Workshop](https://valsamaras.medium.com/android-security-workshop-5eadeb50fba)
* [OWASP Top 10: Static Analysis of Android Application & Tools Used](https://blog.securelayer7.net/static-analysis-of-android-application-tools-used-securelayer7/)
* [Android security checklist: WebView](https://blog.oversecured.com/Android-security-checklist-webview/)
* [Use cryptography in mobile apps the right way](https://blog.oversecured.com/Use-cryptography-in-mobile-apps-the-right-way/)
* [Why Dynamic Code Downloading Can Be Massacred for Your Apps: a Google Example](https://blog.oversecured.com/Why-dynamic-code-loading-could-be-dangerous-for-your-apps-a-Google-example/)
* [Arbitrary code execution on Facebook for Android through download feature](https://dphoeniixx.medium.com/arbitrary-code-execution-on-facebook-for-android-through-download-feature-fb6826e33e0f)
* [Android Webview Exploited](https://www.nuckingfoob.me/android-webview-csp-iframe-sandbox-bypass/index.html)
* [Android: Gaining access to\* Content Orders](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/)
* [Exploiting memory corruption on Android events](https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/)
* [Two Weeks of Samsung Devices Sple: Part 1](https://blog.oversecured.com/Two-weeks-of-securing-Samsung-devices-Part-1/)
* [Two Weeks of Samsung Devices Seased: Part 2](https://blog.oversecured.com/Two-weeks-of-securing-Samsung-devices-Part-2/)
* [Evernote: Universal-XSS, theft of all cookies from all sites, and more](https://blog.oversecured.com/Evernote-Universal-XSS-theft-of-all-cookies-from-all-sites-and-more/)
* [Interception of Android implicit intents](https://blog.oversecured.com/Interception-of-Android-implicit-intents/)
* [TikTok: three persistent code executions and one theft of simple files](https://blog.oversecured.com/Oversecured-detects-dangerous-vulnerabilities-in-the-TikTok-Android-app/)
* [Oversecured Extraquires Stop Code Executed In the Google Play Core Library](https://blog.oversecured.com/Oversecured-automatically-discovers-persistent-code-execution-in-the-Google-Play-Core-Library/)
* [Persistent execution code in Android's Google Play Core Library: details, explanation and the PoC - CVE-2020-8913](https://blog.oversecured.com/Oversecured-automatically-discovers-persistent-code-execution-in-the-Google-Play-Core-Library/)
* [Android: Access to App Protective Computers](https://blog.oversecured.com/Android-Access-to-app-protected-components/)
* [Android: code execution third via third-party package contexts](https://blog.oversecured.com/Android-arbitrary-code-execution-via-third-party-package-contexts/)
* [24,000 Android apps user data via Firebase blunders](https://www.comparitech.com/blog/information-security/firebase-misconfiguration-report/)
* [The Wolf is Back - Android malware modification](https://blog.talosintelligence.com/2020/05/the-wolf-is-back.html?m=1)
* [Modern Security in Android. Part 1](https://medium.com/knowing-android/modern-security-in-android-part-1-6282bcb71e6c)
* [Modern Security in Android. Part 2](https://medium.com/knowing-android/modern-security-in-android-part-2-743cd7c0941a)
* [Modern Security in Android. Part 3](https://medium.com/knowing-android/modern-security-in-android-part-3-bea8cc6f984f)
* [Android IPC: Part 1 – Introduction](https://blog.hacktivesecurity.com/index.php/2020/04/05/android-ipc-part-1-introduction/)
* [Android IPC: Part 2 – Binder and Service Manager Perspective](https://blog.hacktivesecurity.com/index.php/2020/04/26/android-ipc-part-2-binder-and-service-manager-perspective/)
* [StrandHogg 2](https://thehackernews.com/2020/05/stranhogg-android-vulnerability.html)
* [Towards Discovering and Understanding Task Hijacking in Android](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf)
* [Aarrogya setu spyware analisys](https://blogs.quickheal.com/sure-right-aarogya-setu-app-phone/)
* [Playing Around With The Fuchsia Operating System Security](https://blog.quarkslab.com/playing-around-with-the-fuchsia-operating-system.html)
* [Intercepting traffic from Android Flutter applications](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/)
* [SafetyNet's dreaded hardware attestation](https://www.xda-developers.com/safetynet-hardware-attestation-hide-root-magisk/)
* [Tiltoning in Android 11](https://security.googleblog.com/2020/06/system-hardening-in-android-11.html)
* [Snapchat detection on Android](https://aeonlucid.com/Snapchat-detection-on-Android/)
* [Reversing an Android app Protector, Part 1 – Code Obfuscation & RASP](https://www.pnfsoftware.com/blog/reversing-android-protector-obfuscation/)
* [Reversing an Android app Protector, Part 2 – Assets and Code Encryption](https://www.pnfsoftware.com/blog/reversing-android-protector-encryption/)
* [Reversing an Android app Protector, Part 3 – Code Virtualization](https://www.pnfsoftware.com/blog/reversing-android-protector-virtualization/)
* [Structured fuzzing Android's NFC](https://securitylab.github.com/research/fuzzing_android_nfc/)
* [MMS Exploit Part 1: Introduction to the Samsung Qmage Codec and Remote Attack Surface](https://googleprojectzero.blogspot.com/2020/07/mms-exploit-part-1-introduction-to-qmage.html?m=1)
* [DJI ANDROID GO 4 APPLICATION SECURITY ANALYSIS](https://www.synacktiv.com/en/publications/dji-android-go-4-application-security-analysis.html)
* [B3nac - Android application](https://docs.google.com/presentation/d/15bi5pndttfCzMEMw8GT2oCHCJvHx_a8YszkkSMtp_jE/edit#slide=id.p1)
* Dynamic Analysis of Inside Android Cloning Apps
  * [Part 1](https://darvincitech.wordpress.com/2020/07/18/all-your-crypto-keys-belongs-to-me-in-android-virtual-containers/)
  * [Part 2](https://darvincitech.wordpress.com/2020/10/11/virtual-dynamic-analysis-part-2/)
* Tik-Tok App Analisys
  * [TikTok: Logs, Logs, Logs](https://medium.com/@fs0c131y/tiktok-logs-logs-logs-e93e8162647a)
  * [TikTok: What is an app log?](https://medium.com/@fs0c131y/tiktok-what-is-an-app-log-da70193f875)
  * [TikTok: The disinformation is everywhere](https://medium.com/@fs0c131y/tiktok-the-disinformation-is-everywhere-dc340f3ae86a)
* Exploiting Android Messengers with WebRTC
  * [Part 1](https://googleprojectzero.blogspot.com/2020/08/exploiting-android-messengers-part-1.html)
  * [Part 2](https://googleprojectzero.blogspot.com/2020/08/exploiting-android-messengers-part-2.html)
  * [Part 3](https://googleprojectzero.blogspot.com/2020/08/exploiting-android-messengers-part-3.html)
* [Android Pentesting Labs - Step by Step Guide for](https://medium.com/bugbountywriteup/android-pentesting-lab-4a6fe1a1d2e0)
* [An Android Hacking Primer](https://medium.com/swlh/an-android-hacking-primer-3390fef4e6a0)
* [Secure and Android Device](https://source.android.com/security)
* [Security tips](https://developer.android.com/training/articles/security-tips)
* [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide)
* [Security Testing for Android Cross Platform Application](https://3xpl01tc0d3r.blogspot.com/2019/09/security-testing-for-android-app-part1.html)
* [Dive deep in Android Application Security](https://blog.0daylabs.com/2019/09/18/deep-dive-into-Android-security/)
* [Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
* [Mobile Application Penetration Testing Cheat Sheet](https://github.com/sh4hin/MobileApp-Pentest-Cheatsheet)
* [Android Applications Reversing 101](https://www.evilsocket.net/2017/04/27/Android-Applications-Reversing-101/#.WQND0G3TTOM.reddit)
* [Android Security Guidelines](https://developer.box.com/en/guides/security/)
* [Android WebView Vulnerabilities](https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/)
* [OWASP Mobile Top 10](https://www.owasp.org/index.php/OWASP_Mobile_Top_10)
* [Practical Android Phone Forensics](https://resources.infosecinstitute.com/practical-android-phone-forensics/)
* [Mobile Reverse Engineering Unleashed](http://www.vantagepoint.sg/blog/83-mobile-reverse-engineering-unleashed)
* [Quark-engine - An Obfuscation-Neglect Android Malware Scoring System](https://github.com/quark-engine/quark-engine)
* [Root Detection Bypass By Manual Code Manipulation.](https://medium.com/@sarang6489/root-detection-bypass-by-manual-code-manipulation-5478858f4ad1)
* [GEOST BOTNET - the discovery of a new Android banking trojan](http://public.avast.com/research/VB2019-Garcia-etal.pdf)
* [Magisk Systemless Root - Detection and Remediation](https://www.mobileiron.com/en/blog/magisk-android-rooting)
* [AndrODet: An adaptive Android obfuscation detector](https://arxiv.org/pdf/1910.06192.pdf)
* [Hands On Mobile API Security](https://hackernoon.com/hands-on-mobile-api-security-get-rid-of-client-secrets-a79f111b6844)
* [Zero to Hero - Mobile Application Testing - Android Platform](https://nileshsapariya.blogspot.com/2016/11/zero-to-hero-mobile-application-testing.html)
* [Android Malware Adventures](https://docs.google.com/presentation/d/1pYB522E71hXrp4m3fL3E3fnAaOIboJKqpbyE5gSsOes/edit)
* [AAPG - Android application testing guide](https://nightowl131.github.io/AAPG/)
* [Bypassing Android Anti-Emulation](https://www.juanurs.com/Bypassing-Android-Anti-Emulation-Part-I/)
* [Bypassing Xamarin Certificate Pinning](https://www.gosecure.net/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/)
* [Configuring Burp Suite With Android Nougat](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)
* [Inspecting Android HTTP with a fake VPN](https://httptoolkit.tech/blog/inspecting-android-http/)
* [Outlook for Android XSS](https://www.cyberark.com/resources/threat-research-blog/outlook-for-android-xss)
* [Universal XSS in Android WebView](https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/)
* [Mobile Blackhat Asia 2020](https://www.blackhat.com/asia-20/briefings/schedule/#track/mobile)
* [Lockscreen and Authentication Improvements in Android 11](https://security.googleblog.com/2020/09/lockscreen-and-authentication.html?m=1)
* [Firefox: How a website can bet all your cookies](https://infosecwriteups.com/firefox-and-how-a-website-could-steal-all-of-your-cookies-581fe4648e8d)
* [Exploiting a Single Instruction Race Condition in Binder](https://blog.longterm.io/cve-2020-0423.html)
* [An iOS hacker try Android](https://googleprojectzero.blogspot.com/2020/12/an-ios-hacker-tries-android.html?m=1)
* [Hack crypto secrets from heap memory to exploit Android application](https://infosecwriteups.com/hack-crypto-secrets-from-heap-memory-to-exploit-android-application-728097fcda3)
* [A Special Attack Surface of the Android System (1): Evil Dialog Box](https://security.oppo.com/en/noticeDetail?notice_only_key=NOTICE-1351377961017942016)
* [Launching Internal & Non-Exported Deeplinks On Facebook](https://ash-king.co.uk/blog/Launching-internal-non-exported-deeplinks-on-Facebook)
* [Reverse Engineering Flutter for Android](https://rloura.wordpress.com/2020/12/04/reversing-flutter-for-android-wip/)
* [Persistant Arbitrary code execution in mass android](https://hackerone.com/reports/1115864)
* [Common Hals When Using In Android](https://blog.oversecured.com/Common-mistakes-when-using-permissions-in-Android/)
* [The art of exploiting UAF by Ret2bpf in Android kernel](https://i.blackhat.com/EU-21/Wednesday/EU-21-Jin-The-Art-of-Exploiting-UAF-by-Ret2bpf-in-Android-Kernel-wp.pdf)
* [Re route Your Intent for Privilege Escalation (A Universal Way to Exploit Android Pending Intents in High profile and System Apps)](https://i.blackhat.com/EU-21/Wednesday/EU-21-He-Re-route-Your-Intent-for-Privilege-Escalation-A-Universal-Way-to-Exploit-Android-PendingIntents-in-High-profile-and-System-Apps.pdf)
* [A Deep Dive in Privacy Dashboard of Top Android Vendors](https://i.blackhat.com/EU-21/Thursday/EU-21-Bin-A-Deep-Dive-into-Privacy-Dashboard-of-Top-Android-Vendors.pdf)
* [Android Component Security | The Four Horsemen](https://www.hebunilhanli.com/wonderland/mobile-security/android-component-security/)
* [Android Application Testing Using Windows 11 and Windows Subsystem for Android](https://sensepost.com/blog/2021/android-application-testing-using-windows-11-and-windows-subsystem-for-android/)
* [Android Awesome Security](https://reconshell.com/awesome-android-security/)
* [Forensic guide to iMessage, WhatsApp, Telegram, Signal and Skype data acquisition](https://blog.elcomsoft.com/2020/04/forensic-guide-to-imessage-whatsapp-telegram-signal-and-skype-data-acquisition/)
* [Malware Uses Corporate MDM as attack vector](https://research.checkpoint.com/2020/mobile-as-attack-vector-using-mdm/)
* [Mobexler Checklist](https://mobexler.com/checklist.htm)
* [Ad Fraud Spotted in Barcode Reader Malware Analysis](https://www.trendmicro.com/en_us/research/20/f/barcode-reader-apps-on-google-play-found-using-new-ad-fraud-technique.html)
* [Researching Confid Messenger Encryption](https://blog.elcomsoft.com/2020/06/researching-confide-messenger-encryption/)
* [Reverse Engineering Snapchat (Part I): Obfuscation Techniques](https://hot3eed.github.io/snap_part1_obfuscations.html)
* [Reverse Engineering Snapchat (Part II): Deobfuscating the Undeobfuscatable](https://hot3eed.github.io/2020/06/22/snap_p2_deobfuscation.html)
* [Firebase Cloud Messaging Service Takeover](https://abss.me/posts/fcm-takeover/)
* [Saying Goodbye to My Favorite 5 Minute P1](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)
* [Reverse engineering Flutter apps (Part 1)](https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/)
* [How I Hacked Facebook Again!](https://hitcon.org/2020/slides/How%20I%20Hacked%20Facebook%20Again!.pdf)
* [Instagram\_RCE: Code Execution Vulnerability in Instagram App for Android and iOS](https://research.checkpoint.com/2020/instagram_rce-code-execution-vulnerability-in-instagram-app-for-android-and-ios/)
* [How to UseGhidra to Reverse Engineer Mobile Application](https://infosecwriteups.com/how-to-use-ghidra-to-reverse-engineer-mobile-application-c2c89dc5b9aa)
* [React Native Application Static Analysis](https://suam.wtf/posts/react-native-application-static-analysis-en/)
* [Pentesting Non-Proxy Aware Mobile Applications Without Root/Jailbreak](https://medium.com/@meshal_/pentesting-non-proxy-aware-mobile-applications-65161f62a965)
* [2 Click Remote Code execution in Evernote Android](https://hackerone.com/reports/1377748)
* [Android 13 deep dive: Every change up to DP2, documented](https://blog.esper.io/android-13-deep-dive/)
* [https://valuementor.com/blogs/my-fav-7-methods-for-bypassing-android-root-detection](https://valuementor.com/blogs/my-fav-7-methods-for-bypassing-android-root-detection)

</details>

