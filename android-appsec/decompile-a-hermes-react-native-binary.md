# Decompile a Hermes React Native Binary



1. **Pull APK from device**

```bash
adb shell pm list packages | grep <app_name>
adb shell pm path <package_name>
adb pull /data/app/<package_name>-<random>/base.apk .
```

1.  **Decompile APK resources**

    ```bash
    apktool d base.apk -o output_folder
    ```
2.  **Locate React Native bundle**

    ```bash
    cd output_folder/assets/
    ls
    ```
3.  **Check if Hermes bytecode**

    ```bash
    file index.android.bundle
    ```
4.  **Get Hermes decompiler**

    ```bash
    git clone https://github.com/cognisys/hermes-dec.git
    cd hermes-dec
    pip3 install -r requirements.txt
    ```
5.  **Disassemble Hermes bytecode**

    ```bash
    python3 hbc_disassembler.py ../index.android.bundle disasm_out
    ```
6.  **Decompile to JavaScript**

    ```bash
    python3 hbc_decompiler.py ../index.android.bundle decompiled_out
    ```
7.  **(Optional) Beautify/Deobfuscate JS**

    ```bash
    npx prettier --write decompiled_out/*.js
    ```
