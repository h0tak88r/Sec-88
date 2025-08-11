# SSL Pinning Bypass

{% embed url="https://redhuntlabs.com/wp-content/uploads/2023/07/Ultimate-Guide-to-SSL-Pinning-Bypass-RedHunt-Labs.pdf" %}

### **Bypassing SSL pinning using Xposed \[** JustTrustMe Module **]**

to analyze the network traffic of an Android application is very much important from a penetration tester point of view to find vulnerable endpoints and functionality.

Xposed framework “JustTrustMe”  module: To bypass the spinning Xposed framework “JustTrustMe”  module is used.it helps in disabling the SSL certificate checking.&#x20;

**Step 1**: Download JustTrustMe apk  [here](https://github.com/Fuzion24/JustTrustMe/releases/tag/v.2)

**Step 2**: Goto downloaded the folder of apk and open CLI.

Run “adb install JustTrustMe.apk” and accept the allow option in Mobile at the same time.

**Step 3**: Open Xposed, go to modules and checkmark “JustTrustMe”

‍

<figure><img src="https://cdn.prod.website-files.com/624cc1e34dac8ecb3040000a/624cc60f71dbe707d05ba5bc_004%20(1).png" alt=""><figcaption><p>JustTrustMe Module enabled</p></figcaption></figure>

‍

**Step 4**: Reboot your device.\
Now you will be able to capture the application traffic using the proxy.

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
 objection patchapk s package.apk
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

### SSL Unpinning

{% embed url="https://github.com/ac-pm/SSLUnpinning_Xposed" %}
