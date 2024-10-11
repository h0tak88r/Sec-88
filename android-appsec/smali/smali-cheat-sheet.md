---
description: Little Help with SMALI
---

# SMALI Cheat Sheet

Smali is the assembly language used to represent Android's DEX bytecode. This guide organizes the most important instructions and concepts into a comprehensive and easy-to-understand format, providing clarity on the various components of Smali code.

## Smali File Structure

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

## Method Definitions

**Method Definition**

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

## **Comparisons and Conditionals**

Smali uses conditional instructions to perform comparisons and control the flow of execution.

**Comparison Instructions**

* `if-eq/if-ne`: Compare if equal or not equal.
* `if-lt/if-ge`: Compare less than or greater than/equal to.

**Example**:

```smali
    const/4 v0, 5           # Assign 5 to v0
    const/4 v1, 3           # Assign 3 to v1
    if-lt v0, v1, :label1   # If v0 < v1, jump to label1
```

**Unconditional Jump**

* **goto**: Perform an unconditional jump to a label.

**Example**:

```smali
    goto :label2    # Jumps to label2 unconditionally
```

***

## **Method Invocation**&#x20;

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

***

## **Conditionals and Jumps**

Smali code uses `if-*` instructions to handle conditional logic and `goto` for unconditional jumps.

**Conditionals**

* **`if-eq`**: Jumps if two registers are equal.
* **`if-ne`**: Jumps if two registers are not equal.
* **`if-lt`**: Jumps if the first register is less than the second.

**Unconditional Jumps**

* **`goto`**: Jumps to a label unconditionally.

**Example**:

```smali
    const/4 v0, 0x1        # Load constant 1 into v0
    if-eq v0, v1, :label   # If v0 == v1, jump to label
    goto :nextLabel        # Otherwise, jump to nextLabel
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

## References

{% embed url="http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html" %}
