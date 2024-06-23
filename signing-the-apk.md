# Signing the APK

### Decompiling, Modifying, and Signing Android Apps

### APKTOOL - Decompile

To decompile an APK, you can use the `apktool` command:

```
$ apktool d <apk file>
```

If you encounter problems, try decompiling with the `-r` parameter, which skips the resource files:

```
$ apktool d -r game_test.apk
```

If errors persist, consider using alternative decompilers like `jadx` or `androguard`.

### APKTOOL - Compile

After making modifications, you can rebuild the app:

```
$ apktool b game_test/
```

Ensure you provide the directory path and not the APK file when building.

### &#x20;Creating a New Keystore

To sign the APK, you need to create a keystore. Use the following command:

```
$ keytool -genkey -v -keystore ~/android-app-hack.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 365
```

The alias name can be any identifier you choose. It identifies the correct certificate within the keystore, which can hold multiple certificates.

Before signing the APK, align the file using `zipalign` to ensure all uncompressed data start with a 4-byte alignment. This reduces the RAM required by the application:

```
$ zipalign 4 app-debug.apk outfile.apk
```

The aligned file `outfile.apk` can now be signed.

### Signing the App

Sign the APK with the following command:

```
$ apksigner sign --ks ~/android-app-hack.keystore new-debug.apk
```

This creates a new signed application `new-debug.apk`, ready for installation.

### New Version - Steps

Here is a summary of all commands in the new version of android systems 11,12:

1.  Decompile the APK:

    ```
    $ java -jar apktool_2.5.0.jar d org.secuso.privacyfriendlydicer_8.apk
    ```
2. Modify the SMALI content / `AndroidManifest.xml`.
3.  Rebuild the APK:

    ```
    $ java -jar apktool_2.5.0.jar b org.secuso.privacyfriendlydicer_8
    ```
4.  Navigate to the `dist` directory:

    ```
    $ cd dist
    ```
5.  Align the APK:

    ```
    $ zipalign 4 app-debug.apk new-debug.apk
    ```
6.  Sign the APK:

    ```
    $ apksigner sign --ks ~/tools/keystore/android-app-hack.keystore new-debug.apk
    ```
7.  Install the APK:

    ```
    $ adb install -r new-debug.apk
    ```

#### Blue Box Key Vulnerability

To exploit the Blue Box key vulnerability:

1. Add `classez.dex` to the APK.
2. Use a hex editor (like `ghex`) and search for `classez.dex`.
3. Replace `z` with `s`.
4. Now the APK will have two `classes.dex` files.
5. If the vulnerability exists, the APK will validate and accept the latest added `classes.dex` from the attacker.

This vulnerability allows attackers to inject malicious code into an APK by adding an additional `classes.dex` file and manipulating its name.
