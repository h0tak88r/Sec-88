# iOS Device/Simulator Setup

## 1. Physical

### **Preparing the Device**

* **Factory Reset**: Settings > General > Reset > Erase All Content and Settings
* **Enable Developer Mode**: Settings > Privacy & Security > Developer Mode (requires restart)
* **Disable Lock Screen & Passcode**: For easier frequent access

***

### **Setup Device for Development**

1. **Install Xcode** → follow Software Setup
2. **Connect Device to Xcode** → Window > Devices and Simulators → enable for development
3. **Trust the Device** → Settings > General > Device Management → trust connected Mac
4. **Provisioning Profile** → generate/use profile for app installation & testing

***

### **Jailbreaking the Device**

* **Purpose**: Not always needed, but enables deeper access to apps/data
* **Check supported tools**: [Apple Wiki Jailbreak](https://theapplewiki.com/wiki/Jailbreak)

#### **Popular Jailbreak Tools by iOS Version**

* iOS 15–16 → Dopamine
* iOS 15–17 → palera1n
* iOS 12–14 → Checkra1n
* iOS 11–14.3 → Unc0ver
* iOS 14.x → Taurine / Chimera

#### **Post-Jailbreak**

* **Install Package Manager**: Cydia or Sileo
* **Security Testing Tools**: Frida, SSL Kill Switch, Cycript, Radare2
* **File System Tools**: Filza or iFile

⚠️ Jailbreaking weakens device security and voids Apple warranty. Avoid using main device.

***

### **Installing Apps**

* **Via Xcode**: Compile & run directly
* **From IPA**: Use `ideviceinstaller` (libimobiledevice) or Cydia Impactor or xcode
* **From App Store**: Direct install (limited debug features)

***

### **System Logs & Monitoring**

* **System Logs**: Xcode console or `idevicesyslog`
* **Jailbroken Device Logs**: Install Syslog from Cydia for detailed capture

***

### **Restoring the Device**

* **Factory Reset**: Settings > General > Reset > Erase All Content and Settings
* **Unjailbreak**: Use Cydia Eraser to restore stock iOS

## 2. Simulator

iOS Simulator Setup\
 <a href="#el_1726005943684_341" id="el_1726005943684_341"></a>
---------------------------------------------------------------

To setup Simulator, you need to have XCode installed. If you haven't already, follow [Host Software Setup ](https://www.mobilehackinglab.com/path-player?courseid=ios-appsec\&unit=66c5b9fee8fdad44270acb8e)to install it.\


* After you have installed XCode, open it from Launchpad or Spotlight search.
* As you open XCode for the first time, it will ask you which platform to install. Select iOS 15.5. If it does not shows up, open the XCode's Settings from the top menu:
* In the settings, click the + icon at the bottom left corner and click on iOS...:
* In the filter, search for iOS 15 and Click Download & Install after selecting the latest 15.x version available.
* Once the download is complete, we are ready to create our first virtual iOS device. Open Simulator using Spotlight Search or Launcher and then go to File and click New Simulator
* In the New Simulator window, you can select any OS version and give it a name. For this course, select the OS Version to iOS 15.x and click Create button:

<figure><img src="../.gitbook/assets/image (335).png" alt=""><figcaption></figcaption></figure>

* Once the device has been created, you should see a new virtual device up and running.

<figure><img src="../.gitbook/assets/image (337).png" alt=""><figcaption></figcaption></figure>
