# Intercepting Network Traffic with Burp Suite

### Configuring Burp Suite for iOS Traffic Interception <a href="#el_1726180436803_470" id="el_1726180436803_470"></a>

#### Step 1: Set Up Burp Suite Proxy <a href="#el_1726180649321_568" id="el_1726180649321_568"></a>

1\. Open Burp Suite and go to the **Proxy** tab.\
2\. Click **Options** and verify that a listener is running on port **8080** (default setting) or any port of your choice. Ensure that **"All interfaces"** is selected in the Bind to address field.

#### Step 2: Configure iOS Device Proxy Settings <a href="#el_1726180746608_583" id="el_1726180746608_583"></a>

You need to configure your iOS device to route its traffic through Burp Suite.\
1\. On your iOS device, go to **Settings > Wi-Fi**.\
2\. Tap the **i** icon next to your connected Wi-Fi network.\
3\. Scroll down to **HTTP Proxy** and set it to **Manual**.\
4\. Enter the following details:<br>

* **Server**: The IP address of your computer running Burp Suite (you can find it by running **ifconfig** or **ipconfig** on your computer).
* **Port**: The port Burp Suite is listening on (default is **8080**).

```
Server: 192.168.1.100
Port: 8080
```

### Installing Burp Suite CA Certificate <a href="#el_1726180466117_481" id="el_1726180466117_481"></a>

1\. On your iOS device, open **Safari** and navigate to:

```
http://burp
```

2\. This will automatically download the Burp CA certificate (named **cacert.der**).

#### Step 2: Install the CA Certificate <a href="#el_1726181015701_656" id="el_1726181015701_656"></a>

1. After downloading, navigate to **Settings > General > VPN & Device Management** (or **Profiles & Device Management** depending on the iOS version).
2. You should see the **Burp Suite Professional CA** profile listed. Tap on it and install the certificate.
3. Go to **Settings > General > About > Certificate Trust Settings**.
4. Enable full trust for **Burp Suite Professional CA** by toggling the switch.

### Bypassing SSL Pinning <a href="#el_1726180502633_507" id="el_1726180502633_507"></a>

### Non-Jailbroken Device

1. Frida + Objection

{% embed url="https://infosecwriteups.com/unlocking-potential-exploring-frida-objection-on-non-jailbroken-devices-without-application-ed0367a84f07" %}

2. Patch the App (Non-Jailbroken Devices)

### JailBroken Device

1. #### &#x20;Frida <a href="#el_1726181144243_709" id="el_1726181144243_709"></a>

```bash
# Connect the IOS Device
pip install frida-tools

1. Install it from the Selio 
or
1. Connect to the iOS device via SSH:
ssh root@10.11.1.1

2. Add the Frida repository:
echo "deb https://build.frida.re/ ./" >> /etc/apt/sources.list.d/cydia.list

3. Install the Frida server:
apt update
apt install re.frida.server

4. Start the Frida server:
nohup frida-server &

# Common Commands
frida-ls-devices
frida-ps -U
frida-ps -Uai
## attach frida to an app
frida -U -n DVIA-v2  
## Run Script on the APP
frida-trace -U -n DVIA-v2 -l test.js
## Using fridaCodeShare to Bypass JailBreak
frida --codeshare incogbyte/ios-jailbreak-bypass -f YOUR_BINARY
frida --codeshare incogbyte/ios-jailbreak-bypass -U -p 2516
## discover all called classed and methods
frida-discover -U -n DVIA-v 
## Automatically Trace Function Calls
frida-trace -U -n DVIA-v2 -i "*jailbreak*/i"
frida-trace -U DVIA-v2 -m "*[Jailbreak* *]"
```

#### Hooking Swift Methods Dynamically <a href="#el_1726132013350_1285" id="el_1726132013350_1285"></a>

* Example of searching mangled Swift methods: Run this script to search for mangled methods that (partially) match class **JailbreakDetection** and method **isJailbroken**, and then you can target specific methods to hook.

```java
const className = "JailbreakDetection".toLowerCase();
const methodName = "isJailbroken".toLowerCase();

function searchSwiftExports(className, methodName) {
    var modules = Process.enumerateModulesSync();
    var found = false;

    modules.forEach(function(module) {
        var moduleExports = Module.enumerateExportsSync(module.name);

        moduleExports.forEach(moduleExport => {
            if (-1 < moduleExport.name.toLowerCase().indexOf(className) < moduleExport.name.toLowerCase().indexOf(methodName)) {
                console.log("Found matching", moduleExport.type, "in module", module.name, ":"+ moduleExport.name, "at", moduleExport.address)
                found = true;
            }
        });
    });

    if (!found) {
        console.log("No matching export found!");
    }
}

searchSwiftExports(className, methodName);
```

* #### Manipulating Return Values: This script changes the return value of **isJailbroken** in **JailbreakDetectionViewController** to always return **false**. <a href="#el_1726132029737_1311" id="el_1726132029737_1311"></a>

```bash
var myMethod = Module.findExportByName(null, "$s7DVIA_v232JailbreakDetectionViewControllerC12isJailbrokenSbyF");

if (myMethod) {
    Interceptor.attach(myMethod, {
        onLeave: function (retval) {
            console.log("Original Swift return value:", retval.toInt32());
          	
            // Modify the return value to 'false' (which is 0)
            retval.replace(0);
            
            console.log("Modified Swift return value to false (0)");
        }
    });
} else {
  console.log("Hooking Swift method failed!");
}
```

1. Objection

````bash
# Setting Up Objection for iOS
pip install objection
ssh root@10.11.1.1
nohup frida-server &
--------------------------
# Using Objection for Dynamic Analysis
objection -g DVIA-v2 explore
# Get Environment Details
env
## list the bundles that are loaded by the app,
ios bundles list_bundles
## list the frameworks that are used by the app
ios bundles list_frameworks
-----------------------------
# Common Commands
## Bypass SSL pinning
ios sslpinning disable
## Bypass Jailbreak Detection
ios jailbreak disable
## Bypass TouchID or FaceID
ios ui biometric_bypass
## List Loaded Classes
ios hooking list classes
## Explore Methods of a Class
ios hooking list class_methods JailbreakDetection
## Hook Objective-C Methods
ios hooking watch method "+[JailbreakDetection isJailbroken]" --dump-args --dump-return
## Dumping Keychain Data
ios keychain dump
## Patching a Method at Runtime
ios hooking set return_value "+[JailbreakDetection isJailbroken]" false
## Automating with Objection Scripts
- Example script (disable_security.objection):
```
ios jailbreak disable
ios sslpinning disable
ios ui biometric_bypass
```
objection -g DVIA-v2 explore --script disable_security.objection
````

1. Using SSL Kill Switch 2 (for Jailbroken Devices)

{% embed url="https://github.com/nabla-c0d3/ssl-kill-switch2" %}
