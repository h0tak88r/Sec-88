---
description: >-
  (Class, Object, Constructor, Overloading, Java Access Modifiers, Recursion,
  Instanceof Operator)
---

# Java OOP1

## Java Class and Objects

* An <mark style="color:red;">**object**</mark> is any entity that has a **state** and **behavior**
* A <mark style="color:red;">**class**</mark> is a blueprint for the object. Before we create an object, we first need to define the class.

### Create a class in Java <a href="#create-class" id="create-class"></a>

```java
class ClassName {
  // fields
  // methods
}
```

* <mark style="color:blue;">**fields**</mark> are used to store data
* <mark style="color:blue;">**methods**</mark> are used to perform some operation
* To create an object for bicycle we need to make class first (blueprint)

```java
class Bicycle {
  // state or field
  private int gear = 5;
  // behavior or method
  public void braking() {
    System.out.println("Working of Braking");
  }
}
```

* #### Creating an Object in Java

```java
//Basic Schema
className object = new className();
// For Bicycle Class we can create object with this
Bicycle sportsBicycle = new Bicycle();
Bicycle touringBicycle = new Bicycle();
```

* Fields and methods of a class are also called members of the class.
* **Access Members of a Class**

```java
class Bicycle {
  // field of class
  int gear = 5;
  // method of class
  void braking() {
    ...
  }
}

// create object
Bicycle sportsBicycle = new Bicycle();
// access field and method
sportsBicycle.gear;
sportsBicycle.braking();
```

* **Create objects inside the same class**

```java
class Lamp {
  boolean isOn;
  void turnOn() {
    isOn = true;
    System.out.println("Light on? " + isOn);

  }

  public static void main(String[] args) {    
    // create an object of Lamp
    Lamp led = new Lamp();
    // access method using object
    led.turnOn();
  }
}
```

* **Declaring a Java Method**

```java
returnType methodName() {
  // method body
}
-------------------------
modifier static returnType nameOfMethod (parameter1, parameter2, ...) {
  // method body
}
// calls the method
addNumbers();
```

* **Java Method for Code Re-usability**

```java
public class Main {
  // method defined
  private static int getSquare(int x){
    return x * x;
  }

  public static void main(String[] args) {
    for (int i = 1; i <= 5; i++) {

      // method call
      int result = getSquare(i);
      System.out.println("Square of " + i + " is: " + result);
    }
  }
}

-------------------
//output
Square of 1 is: 1
Square of 2 is: 4
Square of 3 is: 9
Square of 4 is: 16
Square of 5 is: 25
```

### Method overloading?

> Suppose, you have to perform the addition of given numbers but there can be any number of arguments (let’s say either 2 or 3 arguments for simplicity).
>
> In order to accomplish the task, you can create two methods `sum2num(int, int)` and `sum3num(int, int, int)` for two and three parameters respectively. However, other programmers, as well as you in the future may get confused as the behavior of both methods are the same but they differ by name.&#x20;
>
> The better way to accomplish this task is by overloading methods. And, depending upon the argument passed, one of the overloaded methods is called. This helps to increase the readability of the program

* Overloading by changing the number of parameters

```java
class MethodOverloading {
    private static void display(int a){
        System.out.println("Arguments: " + a);
    }
    private static void display(int a, int b){
        System.out.println("Arguments: " + a + " and " + b);
    }
    public static void main(String[] args) {
        display(1);
        display(1, 4);
    }
}
----------------
// output
Arguments: 1
Arguments: 1 and 4
```

* Method Overloading by changing the data type of parameters

```java
class MethodOverloading {
    // this method accepts int
    private static void display(int a){
        System.out.println("Got Integer data.");
    }
    // this method  accepts String object
    private static void display(String a){
        System.out.println("Got String object.");
    }

    public static void main(String[] args) {
        display(1);
        display("Hello");
    }
}
-----------------------------
// Output:
Got Integer data.
Got String object.
```

## Java Constructors

* A <mark style="color:blue;">**constructor**</mark> in Java is similar to a method that is invoked when an object of the class is created.
*   In Java, a constructor is a special method with the same name as the class, invoked when an object is created. It lacks a return type and is used for initializing object attributes. Constructors can be categorized into three types:

    1. **No-Arg Constructor**: Takes no parameters. If declared private, it can only be accessed within the class.
    2. **Parameterized Constructor**: Accepts one or more parameters, allowing for the initialization of object attributes based on provided values.
    3. **Default Constructor**: Created automatically by the compiler if no constructors are defined. Initializes instance variables with default values.

    Constructors can be overloaded, allowing for multiple constructors with different parameter sets. Overloaded constructors are called based on the arguments provided during object creation.

    ```java
    class Main {

      String language;

      // constructor with no parameter
      Main() {
        this.language = "Java";
      }

      // constructor with a single parameter
      Main(String language) {
        this.language = language;
      }

      public void getName() {
        System.out.println("Programming Langauage: " + this.language);
      }

      public static void main(String[] args) {

        // call constructor with no parameter
        Main obj1 = new Main();

        // call constructor with a single parameter
        Main obj2 = new Main("Python");

        obj1.getName();
        obj2.getName();
      }
    }
    ------------------------
    // Output: 
    Programming Language: Java
    Programming Language: Python
    ```

## Java Access Modifiers

Access modifiers in Java control the visibility or accessibility of classes, interfaces, variables, methods, constructors, data members, and setter methods. There are four types of access modifiers in Java:

1. **Default (Package-Private) Access Modifier:**
   * Declarations are visible only within the same package.
   * No explicit keyword is used; it's the default if no modifier is specified.
   *   Example:

       ```java
       package defaultPackage;
       class Logger {
           void message(){
               System.out.println("This is a message");
           }
       }
       ```
2. **Private Access Modifier:**
   * Declarations are visible only within the class.
   *   Example:

       ```java
       class Data {
           private String name;

           // Getter method
           public String getName() {
               return this.name;
           }

           // Setter method
           public void setName(String name) {
               this.name = name;
           }
       }

       public class Main {
           public static void main(String[] main){
               Data d = new Data();
               d.setName("Programiz");
               System.out.println(d.getName()); // Output: The name is Programiz
           }
       }
       ```
3. **Protected Access Modifier:**
   * Declarations are visible within the same package or subclasses.
   *   Example:

       ```java
       class Animal {
           protected void display() {
               System.out.println("I am an animal");
           }
       }

       class Dog extends Animal {
           public static void main(String[] args) {
               Dog dog = new Dog();
               dog.display(); // Output: I am an animal
           }
       }
       ```
4. **Public Access Modifier:**
   * Declarations are visible everywhere.
   *   Example:

       ```java
       // Animal.java file
       // Public class
       public class Animal {
           // Public variable
           public int legCount;

           // Public method
           public void display() {
               System.out.println("I am an animal.");
               System.out.println("I have " + legCount + " legs.");
           }
       }

       // Main.java
       public class Main {
           public static void main(String[] args) {
               Animal animal = new Animal();
               animal.legCount = 4;
               animal.display(); // Output: I am an animal. I have 4 legs.
           }
       }
       ```

These access modifiers help in <mark style="color:blue;">**encapsulation**</mark>, allowing control over which parts of a program can access the members of a class, preventing misuse of data.

### Access Modifiers Summarized in one figure <a href="#figure" id="figure"></a>

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-access-modifiers-public-private-protected-default_0.jpg" alt="Accessibility of all Access Modifiers in Java" height="512" width="512"><figcaption><p>Accessibility of all Access Modifiers in Java</p></figcaption></figure>

## Java Recursion

* **Definition:**
  * A method calling itself is termed a recursive method, and the overall process is known as recursion.

#### How Recursion works? <a href="#how-works" id="how-works"></a>

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-recursive-call.jpg" alt="A function is calling itself" height="247" width="416"><figcaption><p>Working of Java Recursion</p></figcaption></figure>

*   **Example:**

    ```java
    javaCopy codeclass Factorial {
        static int factorial(int n) {
            if (n != 0)
                return n * factorial(n-1);
            else
                return 1;
        }

        public static void main(String[] args) {
            int number = 4, result;
            result = factorial(number);
            System.out.println(number + " factorial = " + result);
        }
    }
    ```
* **How it Works:**
  * A function calls itself (recursive call).
  * Termination condition is crucial to avoid infinite recursion.
* **Advantages:**
  * Simplicity: Recursive solutions are often simpler and easier to understand.
  * Quick Implementation: Less time-consuming to write, debug, and maintain.
* **Disadvantages:**
  * Memory Usage: Recursion uses more memory as each call allocates new storage on the stack.
  * Speed: Generally slower compared to iterative solutions.
* **Recommendation:**
  * Choose recursion for simplicity and ease of understanding.
  * Consider alternatives for performance-critical applications

### Java `instanceof` Operator:

* **Definition:**
  * Checks whether an object is an instance of a particular class or interface.
*   **Syntax:**

    ```java
    objectName instanceof className;
    ```
*   **Example:**

    ```java
    class Main {
        public static void main(String[] args) {
            String name = "Programiz";
            boolean result1 = name instanceof String;
            System.out.println("name is an instance of String: " + result1);

            Main obj = new Main();
            boolean result2 = obj instanceof Main;
            System.out.println("obj is an instance of Main: " + result2);
        }
    }
    ```
*   **Output:**

    ```
    name is an instance of String: true
    obj is an instance of Main: true
    ```
*   **Inheritance Example:**

    ```java
    class Animal {}

    class Dog extends Animal {}

    class Main {
        public static void main(String[] args) {
            Dog d1 = new Dog();
            System.out.println(d1 instanceof Dog);      // true
            System.out.println(d1 instanceof Animal);   // true
        }
    }
    ```
*   **Interface Example:**

    ```java
    interface Animal {}

    class Dog implements Animal {}

    class Main {
        public static void main(String[] args) {
            Dog d1 = new Dog();
            System.out.println(d1 instanceof Animal);  // true
        }
    }
    ```
* **Note:**
  * Used to check if an object is an instance of a specific class or interface.
  * Can be used in inheritance scenarios to check superclass or interface instances.
  * Returns `true` if the object is an instance; otherwise, returns `false`.
  * All classes in Java are inherited from the `Object` class.\
