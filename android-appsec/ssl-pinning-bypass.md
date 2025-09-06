# SSL Pinning Bypass

{% embed url="https://redhuntlabs.com/wp-content/uploads/2023/07/Ultimate-Guide-to-SSL-Pinning-Bypass-RedHunt-Labs.pdf" %}

{% embed url="https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/" %}

### Xposed

**Xposed** is a framework for Android that lets you change how apps and the system behave **without modifying the APKs or flashing a custom ROM**.

* [https://github.com/ViRb3/TrustMeAlready](https://github.com/ViRb3/TrustMeAlready)
* [**https://github.com/Fuzion24/JustTrustMe**](https://github.com/Fuzion24/JustTrustMe)
* [https://github.com/ac-pm/SSLUnpinning\_Xposed](https://github.com/ac-pm/SSLUnpinning_Xposed)&#x20;

### Frida

Frida is a dynamic instrumentation framework that allows you to hook and change the mobile app's logic at runtime. Frida is so powerful that it "requires its own ultimate" guide to list all its  features.

```
xz -d frida-server-17.2.15-android-arm64.xz
mv frida-server-17.2.15-android-arm64 frida-server
adb push frida-server /data/local/tmp/
adb shell
cd /data/local/tmp
chmod 755 frida-server
./frida-server &
frida-ps -Uia | grep -i pinning
frida --codeshare akabe1/frida-multiple-unpinning -U -f <appname>
frida -U -N org.secuso.privacyfriendlydicer
## hook the pplication before running 
frida -U -f org.secuso.privacyfriendlydicer -l hook.js
frida -U -f org.secuso.privacyfriendlydicer -l hook.js --no-pause
```

### Objection

```
pip3 install objection
objection patchapk -s package.apk
objection explore --startup-command 'android sslpinning disable'
```

### Frida Gadget

You can automate this by using the above Objection command:&#x20;

```
objection patchapk -s package.apk
```

Else, you can follow the manual way of patching the apk [described in this guide](https://koz.io/using-frida-on-android-without-root/).&#x20;

Once the APK is patched, install Frida tools on the attacker machine using `pip3 install frida-tools`. After installing, you will see programs like frida, frida-ps, frida-Is-devices on your system.\


Install the patched APK on an Android device and open it. The app waits till Frida connects to the Frida gadget. The output of

<figure><img src="../.gitbook/assets/image (333).png" alt=""><figcaption></figcaption></figure>

### APKLAB

{% embed url="https://apklab.surendrajat.xyz/docs/user-guide/getting-started/" %}

### Android SSL Trustkiller&#xD;

{% embed url="https://github.com/iSECPartners/Android-SSL-TrustKiller" %}

### Inspeckage

{% embed url="https://github.com/ac-pm/Inspeckage" %}

### Flutter Application

* ProxyDroid for global tunneling
* Frida scripts to bypass SSL pinning
* reFlutter
* Modify APK
* [Diable TLS Verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) -> A Frida script that disables Flutter's TLS verification  -> [Read Here](https://wahaz.medium.com/finally-ssl-pinning-for-flutter-bypassed-after-frustration-4573e15ed18e)

### Code to Add in “main.dart” <a href="#id-7c81" id="id-7c81"></a>

```
class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    if (Platform.isAndroid) {
      return super.createHttpClient(context)..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    }

    return super.createHttpClient(context)
      ..findProxy = (uri) {
        return "PROXY IP:PORT";
      }
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}
```

### Modifying “`main()"`: <a href="#id-5d7c" id="id-5d7c"></a>

```
HttpOverrides.global = MyHttpOverrides();
```

With this setup, I could run ProxyDroid and intercept the application’s traffic without needing an SSL pinning bypass.

{% embed url="https://medium.com/@k3r0/how-i-discovered-a-0-click-account-takeover-ato-vulnerability-in-a-flutter-application-74c7a5c4dc70" %}
