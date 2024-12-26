---
description: Little Help with SMALI
---

# SMALI Cheat Sheet

Smali is the assembly language used to represent Android's DEX bytecode. This guide organizes the most important instructions and concepts into a comprehensive and easy-to-understand format, providing clarity on the various components of Smali code.

## Smali File Structure

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Types

| **Syntax** | **Meaning**                   |
| ---------- | ----------------------------- |
| V          | Void                          |
| Z          | Boolean                       |
| B          | Byte                          |
| S          | Short                         |
| C          | Char                          |
| F          | Float                         |
| I          | Int                           |
| J          | Long (64-bit)                 |
| D          | Double (64-bit)               |
| \[         | Array (e.g., `[B` → `byte[]`) |
| L          | Fully qualified class name    |

## Registers / Variables / Assigning

In Dalvik, registers are always 32 bits and can hold any type of value. For 64-bit types like `long` and `double`, two registers are used. There are two key types of registers:

* **Local registers (`Vx`)**: Used for local variables and temporary values.
* **Parameter registers (`Px`)**: Used for passing parameters in functions, with `P0` typically representing the `this` operator.

| **Local (Vx)** | **Param (Px)** |
| -------------- | -------------- |
| V0             | P0             |
| V1             | P1             |
| V2             | P2             |
| V4             | P3             |
| V(...)         | P(...)         |

| **Command**                 | **Description**                                                                                           | **Example (Java/Smali)**                                                                                                                               |
| --------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `move vx,vy`                | Moves the content of vy into vx.                                                                          | <p><code>int a = 12;</code><br><code>mov v0, 0xc</code></p>                                                                                            |
| `const/4 vx,lit4`           | Puts the 4-bit constant into vx. Max value is 7. For higher values, remove `/4` to use `const vx, value`. | <p><code>int level = 3;</code><br><code>const/4 v0, 0x5</code></p>                                                                                     |
| `new-array vx,vy,type_id`   | Generates a new array of `type_id` type and `vy` element size, then stores the reference in `vx`.         | <p><code>byte[] bArr = {0, 1, 2, 3, 4};</code><br><code>const/4 v0, 0x5</code><br><code>new-array v0, v0, [B</code></p>                                |
| `const vx, lit32`           | Puts a 32-bit integer constant into `vx`.                                                                 | <p><code>int level = 10000;</code><br><code>const vx, 0x2710</code></p>                                                                                |
| `const-string vx,string_id` | Puts a reference to a string constant identified by `string_id` into `vx`.                                | <p><code>String name = "Player";</code><br><code>const-string v5, "Player"</code></p>                                                                  |
| `iget vx, vy, field_id`     | Reads an instance field into `vx`, where the instance is referenced by `vy`.                              | <p><code>return this.highScore;</code><br><code>iget v0, p0, Lde/fgerbig/spacepeng/services/Profile;->highScore:I</code><br><code>return v0</code></p> |
| `iput vx,vy, field_id`      | Puts `vx` into an instance field, where the instance is referenced by `vy`.                               | <p><code>this.lastPlayedLevel = lastPlayedLevel2;</code><br><code>iput p1, p0, Lde/fgerbig/spacepeng/services/Profile;->lastPlayedLevel:I</code></p>   |

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Local Registers and Types

Local registers start from `v0` and may go up as needed (e.g., `v0` to `v6`). Not all of these correspond directly to variables; some registers are used for internal operations by the decompiler.

The type of local registers often starts with `L`, indicating a class reference. For example:

* `Ljava/lang/String` → String class

The decompiled code also shows the use of extra registers, e.g., `v5`, for handling function outputs (like `sget-object`).

## Operators

| **Command**        | **Description**                                          | **Example (Java/Smali)**                                                                 |
| ------------------ | -------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `add-int vx,vy,vz` | Calculates `vy + vz` and puts the result into `vx`.      | <p><code>score = score + 1;</code><br><code>add-int/lit8 v5, v5, 0x1</code></p>          |
| `sub-int vx,vy,vz` | Calculates `vy - vz` and puts the result into `vx`.      | <p><code>score = score - 1;</code><br><code>sub-int/lit8 v5, v5, 0x1</code></p>          |
| `mul-int vx,vy,vz` | Multiplies `vz` with `vy` and puts the result into `vx`. | <p><code>bonus = bonus * 50;</code><br><code>mul-int/lit8 v6, v1, 0x32</code></p>        |
| `div-int vx,vy,vz` | Divides `vy` by `vz` and puts the result into `vx`.      | <p><code>bonus = bonus / 2;</code><br><code>div-int v4, v1, 0x2</code></p>               |
| `rem-int vx,vy,vz` | Calculates `vy % vz` and puts the result into `vx`.      | <p><code>Math.abs(step2 % 4);</code><br><code>rem-int/lit8 v0, p1, 0x4</code></p>        |
| `and-int vx,vy,vz` | Calculates `vy AND vz` and puts the result into `vx`.    | <p><code>int result = b &#x26; 127;</code><br><code>and-int/lit8 v1, p3, 0x1f</code></p> |
| `or-int vx,vy,vz`  | Calculates `vy OR vz` and puts the result into `vx`.     | \`int result = b                                                                         |
| `xor-int vx,vy,vz` | Calculates `vy XOR vz` and puts the result into `vx`.    | <p><code>Key = a ^ b;</code><br><code>xor-int v1, v2, v3</code></p>                      |

## IF - ELSE - GOTO

### Comparison with 0

| **Syntax**          | **Description**                |
| ------------------- | ------------------------------ |
| `if-eqz vx, target` | Jumps to `target` if `vx == 0` |
| `if-nez vx, target` | Jumps to `target` if `vx != 0` |
| `if-ltz vx, target` | Jumps to `target` if `vx < 0`  |
| `if-gez vx, target` | Jumps to `target` if `vx >= 0` |
| `if-gtz vx, target` | Jumps to `target` if `vx > 0`  |
| `if-lez vx, target` | Jumps to `target` if `vx <= 0` |

### Comparison against a register&#x20;

Here’s a table summarizing the syntax and descriptions for the conditional comparison commands:

| **Syntax**             | **Description**                 |
| ---------------------- | ------------------------------- |
| `if-eq vx, vy, target` | Jumps to `target` if `vx == vy` |
| `if-ne vx, vy, target` | Jumps to `target` if `vx != vy` |
| `if-lt vx, vy, target` | Jumps to `target` if `vx < vy`  |
| `if-ge vx, vy, target` | Jumps to `target` if `vx >= vy` |
| `if-gt vx, vy, target` | Jumps to `target` if `vx > vy`  |
| `if-le vx, vy, target` | Jumps to `target` if `vx <= vy` |

### GOTO

| **Command**     | **Description**                                                        | **Example (Java/Smali)** |
| --------------- | ---------------------------------------------------------------------- | ------------------------ |
| `goto label`    | Unconditionally jumps to the specified label in the code.              | `goto :label_1`          |
| `goto/16 label` | Unconditionally jumps to a label, used when the target is far in code. | `goto/16 :label_2`       |
| `goto/32 label` | Unconditionally jumps to a label for even farther targets.             | `goto/32 :label_3`       |

## Methods - Objects

Here’s a table summarizing the commands and descriptions for invoking methods in Java/Smali:

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Command</strong></td><td><strong>Description</strong></td><td><strong>Example (Java/Smali)</strong></td></tr><tr><td><code>invoke-virtual {parameters}, methodtocall</code></td><td>Invokes a virtual method with parameters.</td><td><code>this.ds.increaseScore(value);</code><br><br><code>invoke-virtual {v5, v6}, Lde/fgerbig/spacepeng/systems/DirectorSystem;->increaseScore(I)V</code></td></tr><tr><td><code>invoke-direct {parameters}, methodtocall</code></td><td>Invokes a method with parameters without virtual method resolution.</td><td><code>DoubleShot doubleShot = new DoubleShot();</code><br><br><code>invoke-direct {v0}, Lde/fgerbig/spacepeng/components/powerup/DoubleShot;->&#x3C;init>()V</code></td></tr><tr><td><code>invoke-static {parameters}, methodtocall</code></td><td>Invokes a static method with parameters.</td><td><code>MathUtils.random((float) MIN_DELAY, (float) MAX_DELAY);</code><br><br><code>invoke-static {v0, v1}, Lcom/example/MathUtils;->random(FF)F</code></td></tr><tr><td><code>invoke-interface {parameters}, methodtocall</code></td><td>Invokes an interface method.</td><td><code>itrt.hasNext();</code><br><br><code>invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z</code></td></tr><tr><td><code>Sget-object</code></td><td>Retrieves the value of a static object field and puts it into a register</td><td><code>String name = MyClass.staticField;</code><br><br><code>sget-object v0, Lcom/example/MyClass;->staticField:Ljava/lang/String;</code></td></tr></tbody></table>

### **Method Invocation**&#x20;

Different instructions are used depending on whether you are invoking a method statically, virtually, or on an interface.

* **`invoke-virtual`**: Calls a method on an object instance(public method).
* **`invoke-static`**: Calls a static method.
* **`invoke-direct`**: Calls a method on the current object directly (private)(typically constructors).

**Example**:

{% code overflow="wrap" %}
```smali
invoke-static {}, Ljava/lang/System;->gc()V  # Invokes the static method 'gc' from System class
```
{% endcode %}

{% code overflow="wrap" %}
```smali
invoke-virtual {v0}, Ljava/lang/String;->length()I   # Call the length() method on a String object stored in v0
```
{% endcode %}

### Method Definitions

A method in Smali starts with a `.method` directive and is followed by the method signature, return type, and parameters.

**Example**:

```smali
.method public myMethod(I)V  # A method named 'myMethod' that takes an integer and returns void
    .locals 1                    # Defines 1 local register
    return-void                  # Return from the method
.end method
```

***

## **Constants and Assignments**

Smali allows assigning constant values to registers using the `const` family of instructions.

* **const/4**: Load a 4-bit constant into a register.
* **const/16**: Load a 16-bit constant.
* **const/high16**: Load a high 16-bit constant.

**Example**:

```smali
    const/4 v0, 0x1   # Assign the constant 1 to register v0
    const-string v1, "Hello"  # Assign the string "Hello" to register v1
```

***

## **Arrays**

In Smali, arrays are handled with the `new-array` instruction, which creates an array and stores it in a register. Elements are accessed via the `aget` and `aput` instructions.

**Example**:

```smali
    const/4 v0, 3             # Define array length
    new-array v1, v0, [I      # Create an integer array of length 3
    aput v0, v1, 0            # Assign value v0 to array index 0
    aget v2, v1, 1            # Load the value from index 1 into v2
```

***

## **Other Instructions**

* **`move`**: Moves the value from one register to another.
* **`return-void`**: Returns from a method with no value.
* **`return`**: Returns a value from a method.

**Example**:

```smali
    move v0, v1    # Move the value of v1 to v0
    return-void    # End the method with no return value
```

## Useful SMALI snippets

### **Printing Variables/Return Values Using `System.out.println`**

This is a simple and effective way to print variables such as passwords, secrets, or comparison values to logcat. By injecting a `System.out.println` statement into the Smali code, you can monitor the output of specific values in the application logs.

**Java Code:**

```java
String password = "Pa%%w0rd!";
System.out.println(password);
```

**Smali Equivalent:**

You can print the value of a variable by loading it into a register (e.g., `v0`), then using `sget-object` and `invoke-virtual` to print it.

```smali
.line 14
const-string v0, "Pa%%w0rd!"
.line 15
.local v0, "password":Ljava/lang/String;
sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
```

After inserting this code into the Smali file, you can run the app and check the logcat output to see the printed value, which can be useful for debugging or extracting sensitive data.

### **Printing Byte Values as Base64 Encoded Strings**

Often, cryptographic functions store sensitive data like keys or initialization vectors (IVs) as byte arrays. To print these byte arrays in a readable format, you can encode them as Base64 strings and output them.

**Java Code:**

```java
System.out.println(Base64.encodeToString(<byte array>, Base64.DEFAULT));
```

**Smali Equivalent:**

Insert the following code into the existing Smali code. Ensure that the register (`v5` in this case) refers to the correct byte array.

```smali
.line 14
const-string v0, "Pa%%w0rd!"
.line 15
.local v0, "password":Ljava/lang/String;
sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

# Base64 encoding of byte array
const/4 v5, 0x0   # Reference to your byte array
invoke-static {v2, v5}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;
move-result-object v5

# Print the encoded string
sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
invoke-virtual {v1, v5}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
```

This will print the byte array as a Base64-encoded string, making it easier to inspect and understand cryptographic data. You can insert this snippet into any Smali file where byte arrays are processed.

## References

{% embed url="http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html" %}
