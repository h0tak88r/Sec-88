# Android Permissions

### **Android Sandboxing**:

* Android sandboxing is the principle of isolating applications from each other and from the operating system itself to enhance security.
* Each Android application runs in its own sandbox, which means it operates independently from other apps and cannot access their data or resources without proper permissions.
* This sandboxing mechanism helps prevent malicious apps from interfering with other apps or the operating system.

### **App Permissions in AndroidManifest.xml**:

* AndroidManifest.xml is a file in every Android app that describes essential information about the app to the Android system.
* App permissions are declared in the AndroidManifest.xml file to specify what resources and data the app needs access to.
* Permissions are listed using `<uses-permission>` tags, indicating both the type of permission and the level of access required by the app.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapp">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.CAMERA" />
    ...
</manifest>
```

In this example, the app requests permissions to access the internet, fine location, and camera. These permissions need to be declared in the AndroidManifest.xml file to be granted by the user at runtime.

### **Custom Permissions**:

* Custom permissions allow developers to define their own permission levels for controlling access to certain features or data within their apps.
* Developers can declare custom permissions in the AndroidManifest.xml file using the `<permission>` tag.
* Custom permissions are useful for implementing fine-grained access control within an app or for allowing communication between different apps.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapp">
    <permission
        android:name="com.example.myapp.CUSTOM_PERMISSION"
        android:protectionLevel="normal" />
    ...
</manifest>
```

Here, a custom permission named `CUSTOM_PERMISSION` is declared with a protection level of "normal". This permission can be used within the app to control access to specific features or resources.

### **Protection Levels in AndroidManifest.xml**:

* Android permissions have different protection levels, which determine how the system grants or denies access to resources based on the app's request.
* There are four protection levels:
  * **Normal**: Permissions that don't pose a significant risk to user privacy or the device's operation. Granted automatically.
  * **Dangerous**: Permissions that involve accessing sensitive data or performing potentially harmful operations. Must be explicitly granted by the user.
  * **Signature**: Permissions that are granted only if the requesting app is signed with the same digital certificate as the app that declared the permission.
  * **SignatureOrSystem**: A special protection level that only system apps or apps signed with the platform's digital certificate can hold. These permissions are typically reserved for core system functionality.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapp">
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.CAMERA" android:protectionLevel="dangerous" />
    <uses-permission android:name="com.example.myapp.CUSTOM_PERMISSION" android:protectionLevel="signature" />
    ...
</manifest>
```

In this example, the `WRITE_EXTERNAL_STORAGE` permission is marked as "dangerous", meaning it requires explicit user approval. The `CAMERA` permission is also marked as "dangerous". Additionally, the `CUSTOM_PERMISSION` is marked with a protection level of "signature", meaning it's only granted to apps signed with the same certificate.

### Important Files

1. **android\_filesystem\_config.h**:
   * `android_filesystem_config.h` is a header file in the Android source code that defines the mapping between Unix user IDs (UIDs) and the permissions granted to them.
   * It specifies which UIDs have access to certain system resources or capabilities.
   * This file plays a crucial role in determining the default permissions and access rights for various system components and applications.
2. **/etc/permissions/platform.xml**:
   * `platform.xml` is a configuration file located in the `/etc/permissions` directory on Android devices.
   * It defines the default permissions granted to system components and apps on the device.
   * This file lists a set of permissions along with their protection levels and other attributes, which serve as a baseline for app permissions on the device.
3. **/data/system/packages.xml**:
   * `packages.xml` is a file located in the `/data/system` directory on Android devices.
   * It stores information about installed packages (apps) on the device, including their permissions and other metadata.
   * This file is used by the Android system to manage app permissions, package installations, and other related tasks.
