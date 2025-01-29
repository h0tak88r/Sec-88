# Setup Android App Pen-testing environment on M4

{% embed url="https://hassan14045.medium.com/setup-android-app-pen-testing-environment-on-mac-book-m1-d3843e23534" %}

{% embed url="https://www.linkedin.com/pulse/setting-up-android-app-pen-testing-environment-xbxvf" %}

{% embed url="https://m4g0.com/posts/how-to-set-up-a-mobile-pen-testing-environment/" %}

### Install Java

```bash
brew install openjdk
```

### Install Android Command line tools

{% embed url="https://developer.android.com/studio#downloads" %}

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

```bash
mkdir /Library/Android
mkdir /Liberary/Android/sdk
mv cmdline-tools /Liberary/Android/sdk/
cd /Library/Android/sdk/cmdline-tools
mkdir latest
mv * latest/
echo 'export ANDROID_SDK_ROOT=/Library/Android/sdk' >> ~/.zprofile
echo 'export PATH=$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$PATH' >> ~/.zprofile
source ~/.zprofile
sdkmanager --list
```

### Install Emulator

{% code overflow="wrap" %}
```bash
sdkmanager --install "platform-tools" "emulator" "system-images;android-34;google_apis;x86_64"
```
{% endcode %}

### Create and Run an Emulator

{% code overflow="wrap" %}
```bash
sdkmanager --install "system-images;android-34;google_apis;arm64-v8a"                               echo 'export PATH=$PATH:/Library/Android/sdk/emulator' >> ~/.zprofile
source ~/.zprofile
```
{% endcode %}

### Create Android Virtual Device

{% code overflow="wrap" %}
```bash
avdmanager create avd -n my_emulator_arm -k "system-images;android-34;google_apis;arm64-v8a" --force
```
{% endcode %}

### Run the AVD

```bash
emulator -avd my_emulator_arm
```

