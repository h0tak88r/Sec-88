# Setting Up a Mobile Penetration Testing Environment on Debian-Based Linux

This guide covers setting up a mobile testing environment, including installation of Genymotion, Frida, Drozer, APK Signer, Medusa, and Jadx. Each tool is critical for analyzing and testing Android applications in a controlled, virtual environment.

## Install Java

```bash
sudo apt update
sudo apt install default-jre
sudo apt install default-jdk
```

## **Install Genymotion**

Genymotion is a powerful Android emulator ideal for penetration testing.

1. **Download Genymotion**: [Genymotion Official Website](https://www.genymotion.com/download/)
2. **Install**: Follow the installation wizard for your operating system.
3. **Create Android Virtual Devices (AVDs)**: Open Genymotion and add a virtual device by selecting a specific Android version and device model.

## **Install Burp**

{% embed url="https://portswigger.net/burp" %}

## **Frida And Burp on Genymotion** &#x20;

Python is essential for Frida, and most Debian-based systems come with it pre-installed. To verify and install Python if necessary, follow these steps:

### **Verify Python Installation**:

```bash
python3 --version
```

If not installed, use:

```bash
sudo apt update
sudo apt install -y python3 python3-pip
sudo apt install python3.12-venv
```

### **Install Frida** using pip:

```bash
mkdir -p ~/.venvs
python3 -m venv ~/.venvs/frida-env
source ~/.venvs/frida-env/bin/activate 
pip install Frida
pip install frida-tools
```

### **Download the Frida Server** for your emulator’s Android version: [Frida Releases](https://github.com/frida/frida/releases)

```bash
adb shell getprop ro.product.cpu.abi  # result should be  x86
wget https://github.com/frida/frida/releases/download/12.7.20/frida-server-12.7.20-android-x86.xz
unxz frida-server-12.7.20-android-x86.xz
mv frida-server-12.7.20-android-x86 frida-server
```

### **Push Frida Serve and burp** on Genymotion:

```bash
adb push ~/Downloads/cacert.cer /data/local/tmp/cert-der.crt
adb push ~/Downloads/cacert.cer /sdcard/Download/cacert.cer
adb push ~/Downloads/frida-server /data/local/tmp
adb shell chmod 777 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Setup burp proxy

1. Proxy Listener

<figure><img src="../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

2. Proxy settings for WiFi

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

3. Install Certificate

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

## **Setting Up Drozer**

Drozer is a useful Android security framework for penetration testing.

```bash
wget https://github.com/WithSecureLabs/drozer/releases/download/3.0.1/drozer-3.0.1-py3-none-any.whl
mkdir -p ~/.venvs
python3 -m venv ~/.venvs/drozer
 ~/.venvs/drozer/bin/python -m pip install drozer-3.0.1-py3-none-any.whl
 pip install drozer-3.0.1-py3-none-any.whl
source ~/.venvs/drozer/bin/activate
pip install distro
 ~/.venvs/drozer/bin/drozer
```

To use `drozer` globally, add an alias in your shell configuration file (`~/.zshrc` or `~/.bashrc`):

```bash
alias drozer="~/.venvs/drozer/bin/drozer"
```

Then, reload your shell configuration with `source ~/.zshrc` or `source ~/.bashrc`.

## Setting up Jadx

```bash
# Download the latest release
wget https://github.com/skylot/jadx/releases/latest/download/jadx-*.zip

# Unzip the downloaded file
unzip jadx-*.zip

# Move the extracted directory to a known location (e.g., ~/bin/jadx)
mv jadx-* ~/bin/jadx
# Make sure they are in bin/ diredctory and the lib/ directory is in the home directory
```

## Install APKTool

1. Download the Linux [wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool). (Right click, Save Link As `apktool`)
2. Download the [latest version](https://bitbucket.org/iBotPeaches/apktool/downloads) of Apktool.
3. Rename the downloaded jar to `apktool.jar`.
4. Move both `apktool.jar` and `apktool` to `/usr/local/bin`. (root needed)
5. Make sure both files are executable. (`chmod +x`)
6. Try running `apktool` via CLI.

```bash
# Download APKTool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool

# Make it executable
chmod +x apktool

# Move it to a known location (e.g., ~/bin/apktool)
mv apktool ~/bin/apktool

# Download the APKTool jar file
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar -O ~/bin/apktool.jar
```

## Install Dex2Jar

```bash
# Download Dex2Jar
wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip

# Unzip the downloaded file
unzip dex-tools-v2.4.zip

# Move the extracted directory to a known location (e.g., ~/bin/dex2jar)
mv dex-tools-v2.4/ ~/bin/dex2jar
```

## **APK Signer**

APK Signer is required to sign APKs. It comes with the Android SDK’s build tools, so you need to install `android-sdk` to access it.

1.  **Install the Android SDK and APK Signer**:

    ```bash
    sudo apt update
    sudo apt install -y android-sdk
    ```
2.  **Sign an APK**:

    ```bash
    c sign --ks my-release-key.jks --out signed.apk unsigned.apk
    ```

    Replace `my-release-key.jks` with your keystore file and `unsigned.apk` with the file you want to sign.

## Magisk

{% embed url="https://support.genymotion.com/hc/en-us/articles/360011385178-How-to-install-Xposed-EdXposed-LSPosed-Magisk-with-Genymotion-Device-image-PaaS" %}

{% embed url="https://support.genymotion.com/hc/en-us/articles/8957952431389-How-to-install-Magisk-on-Genymotion" %}
