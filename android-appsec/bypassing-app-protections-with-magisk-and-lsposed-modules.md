# Bypassing App Protections with Magisk & LSPosed Modules

### **1. Magisk with Zygisk Enabled**

**Purpose:** Zygisk is Magisk’s new method for injecting modules directly into Android’s Zygote process. It replaces older Riru-based injection methods.

**Why it matters:** Most LSPosed modules require Zygisk to hook app code at runtime.

**Usage:**

* Open Magisk → Settings → **Enable Zygisk**.
* Reboot.
* Verify with `adb shell su -c magisk --zygisk`.

***

### **2. Shamiko**

**Type:** Magisk Zygisk Module **Purpose:** Bypasses **root detection** by hiding the presence of root from apps. It works with Magisk’s **DenyList** (which must be disabled in “Enforce mode” for Shamiko to handle hiding).

**Typical usage:**

* Install via Magisk Modules.
* Disable “Enforce DenyList” in Magisk settings.
* Configure hidden apps via Shamiko.

***

### **3. SSL Pinning Bypass – “Always Trust User Certificates”**

**Type:** LSPosed Module **Purpose:** Forces apps to trust all user-installed certificates, bypassing **certificate pinning** and enabling HTTPS interception with tools like **Burp Suite** or **Charles Proxy**.

**When to use:**

* You need to inspect HTTPS requests from apps that enforce their own CA store.
* Combine with `adb shell settings put global http_proxy ...` or VPN-based interception.

***

### **4. Magisk Hide**

**Type:** Magisk Feature (Legacy) **Purpose:** Old method for hiding root from apps. Mostly replaced by **Shamiko**, but still useful on older Android versions.

**Usage tip:** If using newer Magisk, this may not be available — Shamiko is the modern equivalent.

***

### **5. NoHello**

**Type:** LSPosed Module **Purpose:** Blocks apps that require “developer hello” handshakes or unnecessary startup checks. (Niche, used in certain anti-debug/bypass workflows.)

***

### **6. Hide Debugging**

**Type:** LSPosed Module **Purpose:** Prevents apps from detecting that a debugger is attached. Essential for **dynamic analysis** with Frida, Xposed, or JDWP without triggering anti-debug measures.

***

### **7. Hide My App List**

**Type:** LSPosed Module **Purpose:** Hides installed apps from detection — useful when target apps scan for reverse engineering tools like Frida, Burp, or game cheats.

**Usage for RASP bypass:**

* Add your target app to the module scope.
* Configure it to hide “blacklisted” packages from the app’s view.

***

### **8. I Am Not Developer**

**Type:** LSPosed Module **Purpose:** Bypasses developer mode detection by returning `false` for developer options flags. Useful for apps that refuse to run if developer mode is enabled.

***

### **Workflow Example**

For a typical app with strong protections:

1. **Root the device** with Magisk & enable Zygisk.
2. **Install Shamiko** → hide root.
3. **Enable Hide My App List** → hide tools.
4. **Enable Hide Debugging** → attach debugger safely.
5. **Enable SSL Pinning Bypass** → capture HTTPS traffic.
6. **Use I Am Not Developer** → block dev mode detection.

***

### **Disclaimer**

This guide is for **security research, penetration testing, and educational use**. Do **not** use these methods for malicious activity or without permission — doing so may violate laws and terms of service.
