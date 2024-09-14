---
description: Little Help with SMALI
---

# SMALI

Smali is the assembly language used to represent Android's DEX bytecode. This guide organizes the most important instructions and concepts into a comprehensive and easy-to-understand format, providing clarity on the various components of Smali code.

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

## Registers / Variables / Parameters

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

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

## Local Registers and Types

Local registers start from `v0` and may go up as needed (e.g., `v0` to `v6`). Not all of these correspond directly to variables; some registers are used for internal operations by the decompiler.

The type of local registers often starts with `L`, indicating a class reference. For example:

* `Ljava/lang/String` → String class

The decompiled code also shows the use of extra registers, e.g., `v5`, for handling function outputs (like `sget-object`).

## Locals in SMALI

In the decompiled code, the `.locals` directive indicates the number of local registers (e.g., `.locals 8`). The decompiler might allocate more registers than explicitly declared variables. For instance, `v5` may be used to store intermediate results even if it’s not a Java variable.

## JADX-GUI vs APKTOOL

Comparing the output from two decompilers, **JADX-GUI** and **APKTOOL**, we see slight differences. For example, JADX might show `.registers 18` while APKTOOL shows `.locals 8`. These are naming conventions and don’t impact the actual SMALI code. Both decompilers produce functionally equivalent SMALI code, but the representation can vary.

Personally, I prefer the APKTOOL approach, and I'll be using it throughout the course.

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

* **`invoke-virtual`**: Calls a method on an object instance.
* **`invoke-static`**: Calls a static method.
* **`invoke-direct`**: Calls a method on the current object directly (typically constructors).

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
