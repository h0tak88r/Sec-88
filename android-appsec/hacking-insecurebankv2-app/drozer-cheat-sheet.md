# Drozer Cheat Sheet

> drozer is a security testing framework for Android.
>
> drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Android Runtime, other apps' IPC endpoints and the underlying OS.
>
> drozer provides tools to help you use, share and understand public Android exploits.
>
> drozer is open source software, maintained by WithSecure, and can be downloaded from: [https://labs.withsecure.com/tools/drozer/](https://labs.withsecure.com/tools/drozer/)

1. Download python3 version from [https://github.com/WithSecureLabs/drozer/releases](https://github.com/WithSecureLabs/drozer/releases)
2. Download the Drozer agent apk file from [https://github.com/WithSecureLabs/drozer-agent/releases/tag/3.0.0](https://github.com/WithSecureLabs/drozer-agent/releases/tag/3.0.0)
3.  Install Drozer via command`sudo pip3 install drozer-3.0.2-py3-none-any.whl`

    <figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
4. Install apk file in the emulator via command: `adb install drozer-agent.apk`
5.  Initialize drozer server and get the port&#x20;

    <figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
6.  Now forward traffick to this port and connect drozer console \


    <figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
7. Now here is some usefull drozer commands

```bash
# Starting Session
adb forward tcp:31415 tcp:31415
drozer console connect
drozer console connect --server <ip>

# List Modes
ls
ls activity

# Retrieving package information 
dz> run app.package.list -f sieve  
com.mwr.example.sieve
run app.package.list -f <app name>
run app.package.info -a <package name>

# Identifying the attack surface
run app.package.attacksurface <package name>

# Exploiting Activities
run app.activity.info -a <package name> -u
run app.activity.start --component <package name> <component name>
run app.activity.start --component <package name> <component name> --extra <type> <key> <value>

# Exploiting Content Provider
run app.provider.info -a <package name>
run scanner.provider.finduris -a <package name>
run app.provider.query <uri>
run app.provider.update <uri> --selection <conditions> <selection arg> <column> <data>
run scanner.provider.sqltables -a <package name>
run scanner.provider.injection -a <package name>
run scanner.provider.traversal -a <package name>

# Exploiting Broadcast Receivers
run app.broadcast.info -a <package name>
run app.broadcast.send --component <package name> <component name> --extra <type> <key> <value>
run app.broadcast.sniff --action <action>

# Exploiting Service
run app.service.info -a <package name>
run app.service.start --action <action> --component <package name> <component name>
run app.service.send <package name> <component name> --msg <what> <arg1> <arg2> --extra <type> <key> <value> --bundle-as-obj

```
