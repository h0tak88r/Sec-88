# Frida Cheat Sheet

## Essential Frida CLI Commands

Start your pentesting session with these core commands to manage Frida and interact with apps:

* **List Processes**:\
  `frida-ps -U`\
  Shows running processes on a USB-connected device (`-R` for remote).
* **Spawn App**:\
  `frida -U -f <package_name> -l script.js`\
  Launches an app (e.g., `com.example.app`) and injects `script.js`.
* **Attach to Process**:
  * By Name: `frida -U -n <process_name> -l script.js`
  * By PID: `frida -U -p <PID> -l script.js`\
    Injects script into a running process.
* **Run Without Pausing**:\
  `frida -U -f <package_name> -l script.js --no-pause`\
  Starts app without halting, ideal for automation.
* **Save Output**:\
  `frida -U -f <package_name> -l script.js > log.txt`\
  Redirects console logs to a file.
* **Load Multiple Scripts**:\
  `frida -U -f <package_name> -l script1.js -l script2.js`\
  Injects several scripts sequentially.
* **Interactive REPL**:\
  `frida -U -f <package_name>`\
  Opens a live scripting console for debugging.
* **Trace Native Functions**:\
  `frida-trace -U -i "<function_name>" <package_name>`\
  Auto-traces native functions (e.g., `decrypt`) and generates hook templates.
* **Hook System Process**:\
  `frida -U -p 1 -l script.js`\
  Attaches to `init` (PID 1) for system-wide hooks (needs root).
* **Kill Process**:\
  `frida-kill -U <PID>`\
  Terminates a process by PID for restarts.
* **Check Frida Server**:\
  `adb shell "ps | grep frida"`\
  Verifies if `frida-server` is running on the device.
* **Start Frida Server**:\
  `adb shell "/data/local/tmp/frida-server &"`\
  Runs `frida-server` in the background (adjust path if needed).
* **Explore with Objection**:\
  `objection -g <package_name> explore`\
  Launches Objection for runtime app exploration.
* **Version Check**:\
  `frida --version`\
  Confirms installed Frida version.

**Pro Tip**: Use `frida --help` for more options. Visit [frida.re/docs](https://frida.re/docs/home/) for advanced guides.

***

## Java Hooks

### 1. Hook a Java Method

Log or modify method behavior.

```javascript
Java.perform(function() {
    var Auth = Java.use("com.example.app.Auth");
    Auth.login.implementation = function(username, password) {
        console.log(`[+] Login: ${username}, ${password}`);
        return true; // Force success
    };
});
```

**Use Case**: Bypass authentication or log inputs.\
**Tip**: Return `this.login(username, password)` to keep original behavior.

***

### 2. Hook Method Overloads

Target specific parameter signatures.

```javascript
Java.perform(function() {
    var Utils = Java.use("com.example.app.Utils");
    Utils.process.overload('java.lang.String').implementation = function(data) {
        console.log(`[+] Process: ${data}`);
        return this.process("modified");
    };
});
```

**Use Case**: Alter inputs for overloaded methods.\
**Tip**: Find exact types in decompiled code (e.g., via JADX).

***

### 3. Enumerate Live Instances

Interact with runtime objects.

```javascript
Java.perform(function() {
    Java.choose("com.example.app.User", {
        onMatch: function(instance) {
            console.log(`[+] User: ${instance.username.value}`);
            instance.isAdmin.value = true;
        },
        onComplete: function() {
            console.log("[+] Instance scan done");
        }
    });
});
```

**Use Case**: Escalate privileges or dump session data.\
**Tip**: Verify field names in APK decompilation.

***

### 4. Hook Constructor

Control object initialization.

```javascript
Java.perform(function() {
    var Item = Java.use("com.example.app.Item");
    Item.$init.overload('int').implementation = function(value) {
        console.log(`[+] Item init: ${value}`);
        this.$init(9999); // Max value
    };
});
```

**Use Case**: Set high values for game items or user attributes.\
**Tip**: Useful for apps creating sensitive objects.

***

### 5. Override Parameters

Force specific method inputs.

```javascript
Java.perform(function() {
    var Game = Java.use("com.example.app.Game");
    Game.setScore.implementation = function(score) {
        console.log(`[+] Old score: ${score}`);
        return this.setScore(1000000); // Max score
    };
});
```

**Use Case**: Test edge cases or manipulate state.\
**Tip**: Log inputs to understand default behavior.

***

## Native & Memory Hooks

### 6. Hook Native Function

Intercept calls in `.so` libraries.

```javascript
Interceptor.attach(Module.getExportByName("libnative.so", "decrypt"), {
    onEnter: function(args) {
        console.log(`[+] Decrypt arg: ${args[0].readUtf8String()}`);
    },
    onLeave: function(retval) {
        console.log(`[+] Decrypt result: ${retval.readUtf8String()}`);
    }
});
```

**Use Case**: Capture plaintext from native crypto functions.\
**Tip**: Run `Module.enumerateExports("libnative.so")` to list hookable functions.

***

### 7. Memory Pattern Search

Find byte patterns in memory.

```javascript
Memory.scan(Process.enumerateRanges('rw-'), "41 42 43", {
    onMatch: function(address, size) {
        console.log(`[+] Found at: ${address}`);
    },
    onComplete: function() {
        console.log("[+] Scan complete");
    }
});
```

**Use Case**: Locate hardcoded keys or tokens.\
**Tip**: Use Ghidra/IDA to identify patterns.

***

### 8. Memory Dump

Read raw memory at an address.

```javascript
function dumpMemory(address, size) {
    console.log(hexdump(Memory.readByteArray(ptr(address), size), { length: size }));
}
```

**Use Case**: Extract runtime secrets like keys.\
**Tip**: Combine with `frida-trace` to pinpoint addresses.

***

## Security Bypasses

### 9. Bypass SSL Pinning

Disable pinning for traffic interception.

```javascript
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManager = Java.registerClass({
        name: "com.example.FakeTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var context = SSLContext.getInstance("TLS");
    context.init(null, [TrustManager.$new()], null);
});
```

**Use Case**: Proxy HTTPS traffic with Burp Suite.\
**Tip**: If ineffective, try hooking `OkHttpClient$Builder`.

***

### 10. Bypass Root Detection

Spoof root checks.

```javascript
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.includes("su") || path.includes("magisk")) {
            console.log("[+] Bypassing root path: " + path);
            return false;
        }
        return this.exists();
    };
});
```

**Use Case**: Run apps on rooted devices.\
**Tip**: Also hook custom classes like `RootChecker.isRooted`.

***

### 11. Bypass Emulator Detection

Trick apps into running on emulators.

```javascript
Java.perform(function() {
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function(prop) {
        if (prop.includes("os.name") || prop.includes("os.version")) {
            console.log("[+] Bypassing emulator check");
            return "android";
        }
        return this.getProperty(prop);
    };
});
```

**Use Case**: Test apps that block emulators.\
**Tip**: Check for custom detection logic in decompiled code.

***

## Data & Network Monitoring

### 12. Hook Encryption/Decryption

Capture crypto inputs and outputs.

```javascript
Java.perform(function() {
    var Crypto = Java.use("com.example.app.Crypto");
    Crypto.decrypt.implementation = function(input) {
        console.log(`[+] Decrypt input: ${input}`);
        var result = this.decrypt(input);
        console.log(`[+] Decrypt output: ${result}`);
        return result;
    };
});
```

**Use Case**: Extract plaintext from encrypted data.\
**Tip**: Look for classes named `Cipher`, `Crypto`, or `Utils`.

***

### 13. Monitor Network Traffic

Log HTTP/HTTPS connections.

```javascript
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.connect.implementation = function() {
        console.log(`[+] URL: ${this.getURL()}`);
        return this.connect();
    };
});
```

**Use Case**: Discover API endpoints or third-party services.\
**Tip**: Use with SSL bypass for full traffic visibility.

***

### 14. Hook Shared Preferences

Monitor key-value storage.

```javascript
Java.perform(function() {
    var SP = Java.use("android.content.SharedPreferences");
    SP.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log(`[+] SharedPrefs: ${key}=${value}`);
        return value;
    };
});
```

**Use Case**: Capture auth tokens or settings.\
**Tip**: Hook `Editor.putString` to log writes.

***

## Game & Logic Manipulation

### 15. Modify Game Logic

Alter mechanics (e.g., dice rolls).

```javascript
Java.perform(function() {
    var Dicer = Java.use("com.example.app.Dicer");
    Dicer.rollDice.implementation = function(poolSize, faceNum) {
        console.log(`[+] Rolling: ${poolSize}, ${faceNum}`);
        var result = this.rollDice(poolSize, faceNum);
        for (var i = 0; i < result.length; i++) {
            result[i] = faceNum; // Max roll
        }
        console.log(`[+] Fixed: ${result}`);
        return result;
    };
});
```

**Use Case**: Force high scores or test logic flaws.\
**Tip**: Adapt for any array-based method.

***

### 16. Set High Score

Manipulate leaderboard data.

```javascript
Java.perform(function() {
    var Profile = Java.use("com.example.app.Profile");
    Profile.setHighScore.implementation = function(score) {
        console.log(`[+] Old score: ${score}`);
        return this.setHighScore(999999);
    };
});
```

**Use Case**: Test server-side validation or UI limits.\
**Tip**: Check if scores are client- or server-enforced.

***

## Advanced Techniques

### 17. Trace Method Calls

Log call stacks for debugging.

```javascript
Java.perform(function() {
    var Exception = Java.use("java.lang.Exception");
    Exception.$init.overload().implementation = function() {
        console.log("[+] Stack trace:");
        this.getStackTrace().forEach(function(frame) {
            console.log(`\t${frame}`);
        });
        return this.$init();
    };
});
```

**Use Case**: Map app flow or find hidden methods.\
**Tip**: Combine with specific hooks for context.

***

### 18. Hook Dynamic Class Loading

Monitor runtime-loaded classes.

```javascript
Java.perform(function() {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        console.log(`[+] Loading: ${name}`);
        return this.loadClass(name);
    };
});
```

**Use Case**: Detect obfuscated or anti-tamper code.\
**Tip**: Useful for complex apps.

***

### 19. Enumerate Exports

List native library functions.

```javascript
Module.enumerateExports("libtarget.so").forEach(function(exp) {
    console.log(`[+] Export: ${exp.name} @ ${exp.address}`);
});
```

**Use Case**: Find hookable native functions.\
**Tip**: Run before crafting native hooks.

***

### 20. UI Toast Injection

Display custom messages.

```javascript
Java.perform(function() {
    var Toast = Java.use("android.widget.Toast");
    var Context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    Java.scheduleOnMainThread(function() {
        Toast.makeText(Context, Java.use("java.lang.String").$new("Frida Hook Active!"), 1).show();
    });
});
```

**Use Case**: Confirm hook execution or test UI.\
**Tip**: Always use `scheduleOnMainThread` for UI tasks.

***

### Example: Pentest a Login

1. **Find Class**: Decompile to locate `com.example.app.Auth`.
2.  **Hook Login**:

    ```javascript
    Java.perform(function() {
        var Auth = Java.use("com.example.app.Auth");
        Auth.login.implementation = function(user, pass) {
            console.log(`[+] Login: ${user}, ${pass}`);
            return true;
        };
    });
    ```
3. **Log APIs**: Use network hook for endpoints.
4. **Check Storage**: Hook `SharedPreferences` for tokens.
5. **Bypass Protections**: Apply SSL/root bypass if needed.
