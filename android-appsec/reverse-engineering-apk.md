# Reverse Engineering APK

### **Decompiling / Reversing**

When decompiling APKs, various tools can be used depending on the complexity and obfuscation of the code. The main tools are:

* **APKTool**
* **JADX**
* **Dex2Jar -> JD-GUI**
* **Androguard**

### **JADX**

JADX is a widely used tool for decompiling APKs into Java code. It is open-source and can be installed from its [GitHub repository](https://github.com/skylot/jadx).

**Basic Usage:**

```bash
jadx -d outdir your_app.apk
```

This command decompiles the APK and places the decompiled Java classes into the `outdir` directory.

**Common Parameters:**

* `-r, --no-res`: Do not decode resources (useful to avoid errors during decompilation).
* `--escape-unicode`: Escape non-Latin characters in strings.
* `-j, --threads-count`: Set the number of threads for processing (e.g., `-j 4` for 4 threads).
* `--show-bad-code`: Include "bad code" that might be inconsistent or incorrectly decompiled.
* `--log-level`: Set the log level (e.g., `--log-level error`).

**Deobfuscation Parameters:**

* `--deobf`: Activate deobfuscation.
* `--deobf-min`: Minimum length of name for renaming.
* `--deobf-max`: Maximum length of name for renaming.
* `--deobf-rewrite-cfg`: Force saving the deobfuscation map.
* `--deobf-use-sourcename`: Use the source file name as class name alias.
* `--deobf-parse-kotlin-metadata`: Parse Kotlin metadata to class and package names.

**Flow Chart Generation:** To create a flow chart of functions, use the `--cfg` parameter:

```bash
jadx -d out --cfg your_app.apk
```

Convert the resulting `.dot` files to images with tools like `graphviz` and `pydot`.

### **JADX-GUI**

JADX-GUI provides a graphical interface for viewing and navigating decompiled code. It shares the same core as the command-line version of JADX.

### **DEX2jar**

DEX2jar converts the `classes.dex` file from an APK to a JAR file that can be read by JD-GUI.

**Steps:**

1. Unzip the APK.
2.  Convert `classes.dex` to JAR:

    ```bash
    d2j-dex2jar.sh classes.dex
    ```
3. Open the resulting JAR file with JD-GUI.

### **JD-GUI**

JD-GUI is used to display the classes inside a JAR file in a user-friendly GUI. It does not have special parameters and is straightforward to use.

### **APKTOOL**

APKTOOL is a versatile tool for decompiling and rebuilding APKs, handling both resources and manifest files.

**Basic Usage:**

```bash
apktool d your_app.apk
```

**Common Parameters:**

* `-r`: Do not decompile resource files.
* `--force-manifest`: Ensure the AndroidManifest.xml is decompiled even when using the `-r` parameter.

APKTOOL is essential for tasks that require manipulating resources or rebuilding the APK after modification.

### **Androguard**

Androguard is a powerful tool written in Python for reverse engineering Android applications. It can decompile APKs, analyze the manifest, and generate control flow graphs (CFGs). It is available on [GitHub](https://github.com/androguard/androguard).

**Basic Usage:**

*   **Display Android app manifest:**

    ```bash
    androguard axml path/to/app.apk
    ```
*   **Display app metadata (version and app ID):**

    ```bash
    androguard apkid path/to/app.apk
    ```
*   **Decompile Java code from an app:**

    ```bash
    androguard decompile path/to/app.apk --output path/to/directory
    ```

**Decompiling and Creating CFGs:** To decompile an APK and create control flow graphs:

```bash
androguard decompile -o outputfolder -f png -i someapp.apk --limit "^Lcom/elite/.*"
```

Ensure `graphviz` and `pydot` are installed:

```bash
sudo apt-get install graphviz
pip install -U pydot
```

This command will decompile the app and generate CFGs in the specified format, limited to methods matching the regex `^Lcom/elite/.*`.

**Example CFG:**

* The generated CFGs help trace back the control flow, useful for analyzing heavily obfuscated code.

**Creating Call Graphs:** To create a call graph from an APK:

```bash
androguard cg -o callgraph.gml path/to/app.apk
```

This generates a call graph in the specified format, which can be viewed with graph visualization tools like Gephi.

**Filtering Call Graphs:** Filter methods using regex to manage large call graphs:

```bash
androguard cg -o callgraph.gml --classname "^Lcom/elite/.*" path/to/app.apk
```

Androguard is highly configurable and can output detailed analysis, making it indispensable for thorough reverse engineering and deobfuscation efforts.
