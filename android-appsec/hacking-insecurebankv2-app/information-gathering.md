# Information Gathering

### Analyze traffic using burp

1. Install Apk in the androi emulator&#x20;
2.  Fire up burp suite and configure the proxy to listen to all interfaces on port 8081

    <figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>
3.  Configure proxy settings in the android emulator WIFI settings to be your localip:8081

    <figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>
4. Install Certificate to your emulator by exporting the burp certificate -> rename it to `burp.cer` -> push it to the emulator via `adb push <PATH>` then install it to your device
5. run app.py for your server and proxifiy traffic using burp and use all feature and collect all requests

### Pulling apk from devices

```bash
➜  ~ adb shell
vbox86p:/ # pm list packages | grep -i "insecurebank"
package:com.android.insecurebankv2
vbox86p:/ # pm path com.android.insecurebankv2
package:/data/app/com.android.insecurebankv2-PTvJEwmj-WzQHJux46vKZQ==/base.apk
vbox86p:/ # exit
➜  ~ cd Documents/Android\ AppSec/vulnApps/                        
➜  vulnApps adb pull /data/app/com.android.insecurebankv2-PTvJEwmj-WzQHJux46vKZQ==/base.apk
/data/app/com.android.insecurebankv2-P...d. 21.1 MB/s (3462429 bytes in 0.157s)
➜  vulnApps ls
6_3_SieveLoginBypass.zip  sieve_patched_no_crypto
base.apk                  sieve_patched_no_crypto.apk
```

### Decompiling application

```bash
# conver base.apk to base.jar
./d2j-dex2jar.sh -f ~/path/to/apk_to_decompile.apk  
# using jadx cli or jadx-gui you can get the similar ava source code 
➜  ~ jadx base-dex2jar.jar
➜  ~ jadx-gui 
INFO  - output directory: base-dex2jar
INFO  - loading ...
INFO  - Loaded classes: 6529, methods: 40188, instructions: 1564986
INFO  - Resetting disk code cache, base dir: /home/sallam/.cache/jadx/projects/base-dex2jar-4b505a6f3e3bda1e1de8b834d5846214/code
# Using apktool decompiling the apk
➜  vulnApps apktool d base.apk 
I: Using Apktool 2.9.3 on base.apk
I: Loading resource table...
I: Decoding file-resources...
I: Loading resource table from file: /home/sallam/.local/share/apktool/framework/1.apk
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
I: Regular manifest package...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
➜  vulnApps ls
6_3_SieveLoginBypass.zip  base.apk          sieve_patched_no_crypto
base                      base-dex2jar.jar  sieve_patched_no_crypto.apk
```

* Analyze the code and android manifest.xml `subl base/AndroidManifest.xml`&#x20;
*   Use [drozer](https://github.com/WithSecureLabs/drozer) to give you an overview about the application <[how to do it](https://www.udemy.com/course/the-complete-guide-to-android-bug-bounty-penetration-tests/learn/lecture/23034166#overview)> \
    `run app.package.info -a com.android.insecurebankv2`\
    `run app.package.attacksurface com.android.insecurebannkv2`

    <figure><img src="../../.gitbook/assets/image (16) (1).png" alt=""><figcaption></figcaption></figure>
