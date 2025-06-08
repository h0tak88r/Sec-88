# Understanding iOS Security Basics

<figure><img src="../.gitbook/assets/image (330).png" alt=""><figcaption></figcaption></figure>

iOS, the system powering iPhones and iPads, is built with strong security features to keep your data safe. Let’s break down the key concepts in a simple way and visualize them with a graph.

### 1. Privilege Separation & Sandbox

* **Privilege Separation**: Apps run as a regular user (not admin), while core system processes run as "root." This keeps apps from messing with the system.
* **Sandbox**: Each app lives in its own "bubble" (sandbox), so it can’t access other apps’ data or system files. For example, an app can’t read your messages unless you allow it.

<figure><img src="../.gitbook/assets/image (328).png" alt=""><figcaption></figcaption></figure>

### 2. Data Protection

* iOS uses a special chip called the **Secure Enclave Processor (SEP)** to encrypt your data with a unique key tied to your device.
* When you create a file, it’s encrypted with a 256-bit AES key. This key is locked with another key based on your passcode and device ID.
* There are four protection levels:
  * **Complete Protection**: Data is locked until you unlock your phone.
  * **Protected Unless Open**: Data stays accessible if the file was open before locking.
  * **Protected Until First Unlock**: Data is available after the first unlock after a restart.
  * **No Protection**: Only the device ID protects the data, making it easier to wipe remotely.

### 3. Keychain

* The **Keychain** is like a super-secure vault for sensitive stuff like passwords. Only the app that saved the data (or apps you allow) can access it.
* It’s encrypted with a key tied to your device and passcode, so even if someone knows your passcode, they can’t access it on another device.
* Keychain data sticks around even if you delete the app, so developers should clear it when you install or log out.

Here’s an example of how to clear Keychain data in Swift:

```swift
let userDefaults = UserDefaults.standard
if userDefaults.bool(forKey: "hasRunBefore") == false {
    // Remove Keychain items
    userDefaults.set(true, forKey: "hasRunBefore")
    userDefaults.synchronize()
}
```

### 4. App Capabilities

* Apps are restricted by the sandbox but can request specific permissions, like accessing the camera or location, set during installation.
* For sensitive resources, apps need your explicit permission via pop-up alerts (e.g., “Allow access to photos?”).
* Permissions are defined in the app’s **Info.plist** file. Example:

```xml
<plist version="1.0">
<dict>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>Your location is used for navigation.</string>
</dict>
</plist>
```

### 5. Entitlements

* **Entitlements** are special permissions that let apps do things beyond standard limits, like using Data Protection or sharing Keychain data.
* They’re set in the app’s Xcode project or embedded in the IPA file’s `embedded.mobileprovision`.
