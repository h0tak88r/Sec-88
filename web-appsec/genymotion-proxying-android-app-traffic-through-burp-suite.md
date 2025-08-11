# Genymotion - Proxying Android App Traffic Through Burp Suite

### **General**

List devices:&#x20;

```
Adb devices -l 
```

Connect to the listed device:

```
Adb connect <ip>:<port>
```

Go to shell on connected device:

```
Adb shell
```

### **Openssl Commands for Converting the Burp Cert**

```
openssl x509 -inform DER -in burp.cer -out burp.pem
```

```
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
```

```
mv burp.pem 9a5ba575.0
```

```
adb root
```

```
adb remount
```

```
adb push 9a5ba575.0 /sdcard/
```

```
adb shell
```

```
mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/
```

```
chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

### **Pointing Genymotion at Burp**

```
adb shell settings put global http_proxy localhost:<some port>
```

```
adb reverse tcp:<some port> tcp:<port burp is listening on>
```
