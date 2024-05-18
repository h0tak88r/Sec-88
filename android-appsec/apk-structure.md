# APK structure

1. **META-INF**: Contains verification information like CERT.SF, CERT.RSA, and MANIFEST.MF files, which ensure app integrity and require resigning if any modifications occur.
2. **assets**: Stores developer-controlled resources such as videos, document templates, or code/data for frameworks like Cordova or React-native.
3. **AndroidManifest.xml**: A critical file that describes the app’s components, permissions, and compatibility features. This file is often modified during Appdome’s Fusion process to support selected settings.
4. **classes.dex**: Contains compiled Java/Kotlin code in Dalvik bytecode format. Multiple classes.dex files can exist if needed. Appdome adds and modifies these files during its Fusion process for policy integration and code obfuscation.
5. **kotlin**: Holds Kotlin-specific data if the app is written in Kotlin, which may change based on the Fusion policy.
6. **lib**: Contains native libraries for various processors (e.g., ARM, x86). The presence of these subfolders indicates platform compatibility. Appdome encrypts these files for security.
7. **res**: Contains resources with a predefined hierarchy for different screen orientations, OS versions, and languages. Appdome repacks these files during the Fusion process, often adding new files or altering existing ones.
8. **resources.arsc**: Links code to resources, facilitating the display of appropriate text or assets based on device settings. This file is also repacked by Appdome.

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>
