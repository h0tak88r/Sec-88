# Reverse Engineering

**Prerequisites**

* [DVIA-v2](https://github.com/prateek147/DVIA-v2/blob/master/DVIA-v2.ipa) - download the IPA file
* [Ghidra](https://ghidra-sre.org/) - install in your host or a VM
* **Basic knowledge about reverse engineering and arm64 assembly**\
  To learn more about arm64 (AARCH64 / armv8a) assembly follow our Userland trainings.\
  To learn the basics there are a few good resources you can find online for example:

1. [https://github.com/Siguza/ios-resources/blob/master/bits/arm64.md](https://github.com/Siguza/ios-resources/blob/master/bits/arm64.md)
2. [https://mariokartwii.com/armv8/](https://mariokartwii.com/armv8/)
3. [https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly)

## Decompiling the App <a href="#el_1727115917528_340" id="el_1727115917528_340"></a>

```bash
# IPSW Injstall
brew install blacktop/tap/ipsw
ipsw --help

# Install Swift
MacOS -> just install xcode
sudo apt install -y curl
curl -L https://swiftlygo.xyz/install.sh | bash
sudo swiftlygo install latest
swift --help

# Extract the IPA File
unzip ./DVIA-v2.ipa

# Locate the App Binary
./Payload/DVIA-v2.app/DVIA-v2

# Dumping Objective-C Classes Using class-dump
ipsw class-dump ./Payload/DVIA-v2.app/DVIA-v2 --headers -o ./class_dump

# Dumping Swift Classes Using swift-dump
ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 > ./swift_dump_mangled.txt
ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 --demangle > ./swift_dump_demangled.txt
```

## Automation for Decompiling

```bash
#!/bin/bash

# Check if an IPA file was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <path_to_ipa_file>"
  exit 1
fi

IPA_FILE="$1"

# Check if the IPA file exists
if [ ! -f "$IPA_FILE" ]; then
  echo "[@] Error: IPA file not found!"
  exit 1
fi

# Get the app name from the IPA file
APP_NAME="$(basename ""$IPA_FILE"" .ipa)"
OUTPUT_DIR="$(dirname ""$IPA_FILE"" | xargs readlink -f)"

# Create output directory
OUTPUT_DIR="$OUTPUT_DIR/$APP_NAME"
mkdir -p "$OUTPUT_DIR"

# Unzip the IPA contents
UNZIP_DIR="$OUTPUT_DIR/_extracted"
echo "[*] Extracting IPA contents..."
mkdir -p "$UNZIP_DIR"
unzip -q "$IPA_FILE" -d "$UNZIP_DIR"

# Locate the .app directory
APP_PATH=$(find "$UNZIP_DIR" -name "*.app" -type d)

if [ -z "$APP_PATH" ]; then
  echo "[@] No .app found in $UNZIP_DIR, exiting..."
  exit 1
fi

BINARY="$APP_PATH/$(basename ""$APP_PATH"" .app)"

# Check if the binary exists (file without an extension in the .app folder)
if [ ! -f "$BINARY" ]; then
  echo "[@] No binary found in $APP_PATH, exiting..."
  exit 1
fi

# Create directories for class dumps
CLASS_DUMP_OUTPUT="$OUTPUT_DIR/class_dump"
SWIFT_DUMP_OUTPUT="$OUTPUT_DIR/swift_dump"
mkdir -p "$CLASS_DUMP_OUTPUT"
mkdir -p "$SWIFT_DUMP_OUTPUT"

# Dump Objective-C classes using class-dump
echo "[*] Dumping Objective-C classes for $APP_NAME..."
ipsw class-dump "$BINARY" --headers -o "$CLASS_DUMP_OUTPUT"

# Dump Swift classes using swift-dump
echo "[*] Dumping Swift classes for $APP_NAME..."
ipsw swift-dump "$BINARY" > "$SWIFT_DUMP_OUTPUT/$APP_NAME-mangled.txt"
ipsw swift-dump "$BINARY" --demangle > "$SWIFT_DUMP_OUTPUT/$APP_NAME-demangled.txt"

echo "[+] Decompilation completed for $APP_NAME"
```

{% embed url="https://www.mobilehackinglab.com/path-player?courseid=ios-appsec&unit=66ded39f2bae13a9b9093c22Unit" %}

## Analyzing Decompiled Output from an IPA File

**1 — Goals and workflows**

1. **Goal:** turn raw decompiled symbols into an understanding of app behaviour, attack surface, and risky logic (network, auth, crypto, IPC, privileged checks).
2. **High-level workflow:**
   * **Static reconnaissance:** read Objective-C headers and demangled Swift symbols to map structure and likely behaviour.
   * **Prioritization:** mark classes/methods that touch secrets, I/O, network, system APIs, or platform checks.
   * **Deeper static analysis:** open interesting routines in a disassembler/decompiler to inspect control flow and data handling.
   * **Dynamic analysis:** instrument or run the app to observe real behaviour, confirm hypotheses, and gather run-time data.
   * **Iterate:** refine targets and repeat.

***

**2 — Reading Objective-C headers (class-dump output) — what to look for**

Focus on structure, not perfect semantics.

Essentials:

* **Class names & inheritance:** identify controllers, managers, clients (e.g., `*Manager`, `*Client`, `*Controller`, `*Handler`). These often centralize logic.
* **Protocols & delegates:** they reveal callback flows and event pathways.
* **Properties & instance variables:** note fields typed as `NSString`, `NSData`, `NSDictionary`, `NSUserDefaults`, `Keychain` wrappers — potential secret storage.
* **Method signatures:** methods named with `login`, `authenticate`, `fetch`, `send`, `encrypt`, `decrypt`, `verify`, `jailbreak`, `root`, `entitlement` deserve higher priority.
* **I/O and parsing methods:** anything reading/writing files, parsing JSON/XML, serializing/deserializing data.
* **Network call wrappers:** methods accepting URLs, forming requests, or using `NSURLSession`/`CFNetwork` are high-value.

How to triage:

* Tag each class as **Informational / Sensitive / High-priority**.
* Build a quick map: `UI → Controller → Manager → Network/Storage` so you can trace data flow.

***

**3 — Inspecting Swift symbols (swift-dump) — how to extract meaning**

Swift lacks header files; symbols give hints.

What to extract:

* **Class/struct names and fields:** names often describe responsibilities (`UserStore`, `NetworkClient`, `CryptoService`).
* **Method names and argument types:** demangled methods show actions (`loginButtonTapped`, `fetchData`, `encryptData`).
* **Accessors and computed properties:** getter/setter symbols indicate where state is read and mutated.
* **Static/utility functions:** often hold config, constants, or helper logic.

Inferences:

* Map UI fields (text fields, buttons) to backend calls by name similarity.
* Note methods that hint at platform checks (e.g., `isJailbroken`, `hasRootedFilesystem`) or obfuscation helpers (e.g., `reveal`, `obfuscate`).

***

**4 — From symbols to hypotheses: what to test**

Form simple, testable hypotheses from static evidence:

* “This class reads credentials from a text field then calls `NetworkClient.sendAuth`; check if credentials are sent in plaintext.”
* “This routine calls `KeychainWrapper.save(token:)`; check whether token protection uses proper attributes.”
* “A `JailbreakChecker` or `Obfuscator` is referenced; check what values it returns at runtime and where they’re consumed.”

Write each hypothesis as: **(Where) → (What) → (How to confirm)**.

***

**5 — Deeper static analysis (disassembler / decompiler)**

When a method looks important, move to a Disassembler (Ghidra, IDA, Hopper):

What to inspect:

* **Control flow:** branches that gate privileged paths or feature flags.
* **Constants & embedded data:** strings, URLs, magic numbers, salts.
* **Opaque calls / indirections:** observe calls where pointers or function tables are used — these often represent vtables, callbacks, or obfuscated logic.
* **Crypto usage:** calls into CommonCrypto/CryptoKit or custom routines; identify inputs/outputs.

Renaming: rename meaningless locals/temps to meaningful names (e.g., `obfuscatorPtr`) to help reasoning.

Limit yourself to _understanding_ logic: identify where sensitive decisions are made and which inputs affect them.

***

**6 — Runtime/dynamic analysis (general approach) (frida)**

Purpose: confirm static hypotheses and observe live values.

General steps (tool-agnostic):

* **Run the app in a controlled environment** (emulator/device under test) and exercise the functionality of interest.
* **Log or observe:** capture network traffic, filesystem access, API calls, and key return values to see real data shapes.
* **Probe interfaces:** call methods that appear to return flags (e.g., `isDeviceSecure`) and record outputs for different environments.
* **Trace data flow:** observe how input (user text, files, system state) propagates to sinks (network, storage, system APIs).

Be careful: do not run instrumentation on production systems or without authorization.

{% embed url="https://8ksec.io/advanced-frida-usage-part-2-analyzing-signal-and-telegram-messages-on-ios/" %}

Example: To analyze the **reveal** method, we can hook them using the following **Frida** script:

```javascript
// Helper functions
function messageFromArray(arr) {
    var reversed = arr.reverse();
    var m = '';
    for (var i = 0; i < reversed.length; i++) {
        if (reversed[i] == 0) {
            break;
        }
        m += String.fromCharCode(reversed[i]);
    }
    return m;
}

function getMessage(x0, x1){
    var firstByte = x0.toString().slice(0,4);
    var message = '';
    if (firstByte == 0xf0) {
        // add 32 because of the header
        var loc = x1.add(32);
        message = Memory.readUtf8String(loc);
    } else {
        // small string, less than 16 bytes
        var firstArg = x0.toString().slice(2);
        var firstChars = [];

        // read bytes from x0 and convert them to int
        for (var i = 0; i < firstArg.length; i += 2) {
            var ch = parseInt(firstArg.slice(i, i+2), 16);
            firstChars.push(ch);
        }
        // convert those bytes to string
        var firstMessage = messageFromArray(firstChars);

        // we start reading from the second byte because in
        // maximum number of characters is 7 in x1 for Swift.String
        var secondArg = x1.toString().slice(4);
        var secondChars = [];
        // read bytes from x1 and convert them to int
        for (var i = 0; i < secondArg.length; i += 2){
            var ch = parseInt(secondArg.slice(i, i+2), 16);
            secondChars.push(ch);
        }

        // append the strings from both x0 and x1
        var secondMessage = messageFromArray(secondChars);

        message = firstMessage + secondMessage;
    }
    return message
}

// Hook methods
var myMethod = Module.findExportByName(null, "$s7DVIA_v210ObfuscatorC6reveal3keySSSays5UInt8VG_tF");

if (myMethod) {
    Interceptor.attach(myMethod, {
        onEnter: function (args) {
            console.log("Hooked Swift method: Obfuscator +reveal");
        },
        onLeave: function (retval) {
            var message = getMessage(this.context.x0, this.context.x1);
            console.log("Returned Swift value:", message, "(", retval, ")");
        }
    });
} else {
  console.log("Hooking Swift method failed!");
```

***

**7 — Instrumentation tips (non-code, conceptual)**

If you use dynamic instrumentation frameworks, keep these high-level strategies in mind:

* **Hook high-value functions, not everything:** focus on functions that return strings, booleans, or perform I/O.
* **Capture arguments and return values:** this tells you what data the app is acting on and what it expects.
* **Watch for heap vs. inline storage:** short strings may be stored in registers/stack, longer ones on the heap—know your tool’s string-reading limits.
* **Alter outputs carefully for testing hypotheses:** e.g., replace a returned flag with the opposite and observe behavior — but only in controlled, authorized testing.

Again: this is methodology; do not treat this as an executable script.

***

**8 — Common patterns that indicate risk**

**Hardcoded secrets:** strings that look like API keys, tokens, or salts.

* **Insecure network usage:** plain HTTP endpoints or custom, unauthenticated protocols.
* **Poor storage of secrets:** sensitive data in files, `NSUserDefaults`, or unprotected SQLite.
* **Weak crypto wrappers:** custom or non-standard crypto functions that reimplement known algorithms.
* **Device/environment checks:** explicit jailbreak/root checks, emulation checks, or integrity checks — these can affect testing strategy and explain conditional behaviour.

***

**9 — Practical checklist (quick)**

* [ ] Map classes → responsibilities.
* [ ] Flag methods dealing with network, auth, crypto, file I/O, or system checks.
* [ ] Inspect disassembly for constants and opaque call sites.
* [ ] Form hypotheses: inputs → processing → outputs.
* [ ] Use dynamic observation to confirm or refute hypotheses.
* [ ] Document findings, including exact symbol names, file/line (if available), and observed runtime values.

## Patching an app with Ghidra <a href="#el_1729504513641_341" id="el_1729504513641_341"></a>

#### 1. Extract the binary from the app <a href="#el_1729515459539_466" id="el_1729515459539_466"></a>

DVIA-V2 (.ipa renamed to .zip) - Payload - DVIA-v2.app -> DVIA-v2

<figure><img src="../.gitbook/assets/image (338).png" alt=""><figcaption></figcaption></figure>

#### 2. Load the binary in Ghidra <a href="#el_1729515568466_567" id="el_1729515568466_567"></a>

* Open Ghidra., create a new project and import the DVIA-v2 binary, via file -> batch import:
* Double-click on the file name after the batch import finished.
* Click "Yes" on the question regarding analyze now in Ghidra, and "Check Decompiler Parameter ID" next to the default Analysis options, and click on "Analyze":

<figure><img src="../.gitbook/assets/image (339).png" alt=""><figcaption></figcaption></figure>

***

#### 3. Patch the binary in Ghidra <a href="#el_1729515589658_579" id="el_1729515589658_579"></a>

* Search in the "Symbol Tree" for a function with the name "isJailbroken".
*   Find the **local\_11** variable **in the return statement of the decompiled 'isJailbroken' function,**&#x20;

    which has a signature like: \
    `byte JailbreakDetection::isJailbroken(undefined8 param_1,undefined8 param_2).`
* Right click on the matching line in the assembly code "**and w0, w8, #01**" -> Patch instruction
* Change "**and  w0, w8, #01**" to "**mov  w0, #0x0**". \
  This will result in the function (isJailbroken) always returning 0 (w0 is the register containing function return values and will always get the value 0x0 now via the MOV instruction) instead of the bitwise compare (AND instruction), depending on the function logic.
* Save the modified binary via file -> export program, and pick "Original File":
* Replace the original DVIA-V2 binary with the patched DVIA-V2 binary in the Payload folder.
* Zip the modified "Payload" as new IPA, for exaple with zip: `zip -r DVIA-V2-patched.ipa Payload/`
*

<figure><img src="../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (341).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (342).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (344).png" alt=""><figcaption></figcaption></figure>
