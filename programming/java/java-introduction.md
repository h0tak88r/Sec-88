# Java Introduction

## Java JDK, JRE and JVM

* **JVM (Java Virtual Machine)** is an abstract machine that enables your computer to run a Java program.

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

* **JRE (Java Runtime Environment)** is a software package that provides Java class libraries, Java Virtual Machine (JVM), and other components that are required to run Java applications.
* **JDK (Java Development Kit)** is a software development kit required to develop applications in Java. When you download JDK, JRE is also downloaded with it.

### What is JDK? <a href="#jdk" id="jdk"></a>

JDK (Java Development Kit) is a software development kit required to develop applications in Java. When you download JDK, JRE is also downloaded with it.

In addition to JRE, JDK also contains a number of development tools (compilers, JavaDoc, Java Debugger, etc).

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-development-kit.jpg" alt="JDK contains JRE and other tools to develop Java applications." height="101" width="370"><figcaption><p>Java Development Kit</p></figcaption></figure>

If you want to develop Java applications, [download JDK](http://www.oracle.com/technetwork/java/javase/downloads/index-jsp-138363.html).

***

### Relationship between JVM, JRE, and JDK.

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/jdk-jre-jvm.jpg" alt="JRE contains JVM and class libraries and JDK contains JRE, compilers, debuggers, and JavaDoc" height="346" width="384"><figcaption><p>Relationship between JVM, JRE, and JDK</p></figcaption></figure>

## Java Operators

Operators in Java can be classified into 5 types:

1. Arithmetic Operators
2. Assignment Operators
3. Relational Operators
4. Logical Operators
5. Unary Operators
6. Bitwise Operators

### Arithmetic Operator

| Operator | Operation                                   |
| -------- | ------------------------------------------- |
| `+`      | Addition                                    |
| `-`      | Subtraction                                 |
| `*`      | Multiplication                              |
| `/`      | Division                                    |
| `%`      | Modulo Operation (Remainder after division) |

### Logical Operators

| Operator | Description          |
| -------- | -------------------- |
| `~`      | Bitwise Complement   |
| `<<`     | Left Shift           |
| `>>`     | Right Shift          |
| `>>>`    | Unsigned Right Shift |
| `&`      | Bitwise AND          |
| `^`      | Bitwise exclusive OR |

### Java Unary Operators

| Operator | Meaning                                                                          |
| -------- | -------------------------------------------------------------------------------- |
| `+`      | **Unary plus**: not necessary to use since numbers are positive without using it |
| `-`      | **Unary minus**: inverts the sign of an expression                               |
| `++`     | **Increment operator**: increments value by 1                                    |
| `--`     | **Decrement operator**: decrements value by 1                                    |
| `!`      | **Logical complement operator**: inverts the value of a boolean                  |

### Java Assignment Operators

| Operator | Example   | Equivalent to |
| -------- | --------- | ------------- |
| `=`      | `a = b;`  | `a = b;`      |
| `+=`     | `a += b;` | `a = a + b;`  |
| `-=`     | `a -= b;` | `a = a - b;`  |
| `*=`     | `a *= b;` | `a = a * b;`  |
| `/=`     | `a /= b;` | `a = a / b;`  |
| `%=`     | `a %= b;` | `a = a % b;`  |

### Java Relational Operators

| Operator | Example   | Equivalent to |
| -------- | --------- | ------------- |
| `=`      | `a = b;`  | `a = b;`      |
| `+=`     | `a += b;` | `a = a + b;`  |
| `-=`     | `a -= b;` | `a = a - b;`  |
| `*=`     | `a *= b;` | `a = a * b;`  |
| `/=`     | `a /= b;` | `a = a / b;`  |
| `%=`     | `a %= b;` | `a = a % b;`  |

### Java Logical Operators

| Operator            | Example                          | Meaning                                                    |
| ------------------- | -------------------------------- | ---------------------------------------------------------- |
| `&&` (Logical AND)  | expression1 **&&** expression2   | `true` only if both expression1 and expression2 are `true` |
| `\|\|` (Logical OR) | expression1 **\|\|** expression2 | `true` if either expression1 or expression2 is `true`      |
| `!` (Logical NOT)   | **!**expression                  | `true` if expression is `false` and vice versa             |

### Java Bitwise Operators&#x20;

| Operator | Description          |
| -------- | -------------------- |
| `~`      | Bitwise Complement   |
| `<<`     | Left Shift           |
| `>>`     | Right Shift          |
| `>>>`    | Unsigned Right Shift |
| `&`      | Bitwise AND          |
| `^`      | Bitwise exclusive OR |

## Java Basic Input and Output

### Java Output <a href="#output" id="output"></a>

```java
System.out.println(); or
System.out.print(); or
System.out.printf();
```

### Java Input <a href="#input" id="input"></a>

```java
import java.util.Scanner;
// create an object of Scanner
Scanner input = new Scanner(System.in);
// take input from the user
int number = input.nextInt();
```
