# Java OOP2

### Java Inheritance:

* **Definition:**
  * Inheritance is an Object-Oriented Programming (OOP) concept that allows creating a new class (subclass) from an existing class (superclass).
*   **Syntax:**

    ```java
    class Subclass extends Superclass {
        // fields and methods of Subclass
    }
    ```
*   **Example:**

    ```java
    class Animal {
        String name;
        public void eat() {
            System.out.println("I can eat");
        }
    }

    class Dog extends Animal {
        public void display() {
            System.out.println("My name is " + name);
        }
    }

    class Main {
        public static void main(String[] args) {
            Dog labrador = new Dog();
            labrador.name = "Rohu";
            labrador.display();
            labrador.eat();
        }
    }
    /*
    Output:
    My name is Rohu
    I can eat
    */
    ```
* **Inheritance Types:**
  1. **Single Inheritance:**
     * One subclass extends one superclass.
     * Example: `Class A extends Class B`.
  2. **Multilevel Inheritance:**
     * Subclass extends another subclass, creating a chain.
     * Example: `Class B extends Class A` and `Class C extends Class B`.
  3. **Hierarchical Inheritance:**
     * Multiple subclasses extend a single superclass.
     * Example: `Class B extends Class A` and `Class C extends Class A`.
  4. **Multiple Inheritance:**
     * One subclass extends multiple superclasses.
     * Note: Java does not support multiple inheritance directly.
  5. **Hybrid Inheritance:**
     * Combination of two or more types of inheritance.

### Method Overriding

In Java, method overriding occurs when a subclass provides a specific implementation for a method that is already defined in its superclass. Here's a summarized breakdown:

1.  **Basic Method Overriding:**

    * If the same method is present in both the superclass and the subclass, the method in the subclass overrides the one in the superclass.
    * The `@Override` annotation is used to inform the compiler about the intention to override, though it's not mandatory.

    ```java
    // Example 1: Method Overriding
    class Animal {
       public void displayInfo() {
          System.out.println("I am an animal.");
       }
    }

    class Dog extends Animal {
       @Override
       public void displayInfo() {
          System.out.println("I am a dog.");
       }
    }

    class Main {
       public static void main(String[] args) {
          Dog d1 = new Dog();
          d1.displayInfo(); // Output: I am a dog.
       }
    }
    ```
2.  **Using `super` Keyword:**

    * The `super` keyword is used in the subclass to call the overridden method of the superclass.

    ```java
    // Example 2: Use of super Keyword
    class Animal {
       public void displayInfo() {
          System.out.println("I am an animal.");
       }
    }

    class Dog extends Animal {
       public void displayInfo() {
          super.displayInfo();
          System.out.println("I am a dog.");
       }
    }

    class Main {
       public static void main(String[] args) {
          Dog d1 = new Dog();
          d1.displayInfo();
          // Output:
          // I am an animal.
          // I am a dog.
       }
    }
    ```
3.  **Access Specifiers in Method Overriding:**

    * The access specifier in the subclass should provide larger access than the access specifier in the superclass.

    ```java
    // Example 3: Access Specifier in Overriding
    class Animal {
       protected void displayInfo() {
          System.out.println("I am an animal.");
       }
    }

    class Dog extends Animal {
       public void displayInfo() {
          System.out.println("I am a dog.");
       }
    }

    class Main {
       public static void main(String[] args) {
          Dog d1 = new Dog();
          d1.displayInfo(); // Output: I am a dog.
       }
    }
    ```
4.  **Overriding Abstract Methods:**

    In Java, abstract classes are created to be the superclass of other classes. And, if a class contains an abstract method, it is mandatory to override it.

Method overriding is crucial for achieving polymorphism in Java and providing specific behaviors in subclasses while maintaining a consistent interface in the superclass.

### Java Abstract Class <a href="#abstract-class" id="abstract-class"></a>

In Java, abstract classes and methods facilitate abstraction, allowing developers to hide implementation details and focus on essential information. Here's a summarized overview:

1.  **Abstract Class:**

    * Abstract classes in Java cannot be instantiated; we use the `abstract` keyword to declare them.
    * Abstract classes can have both regular methods and abstract methods (methods without a body).
    * If a class contains an abstract method, the class itself must be declared as abstract.

    ```java
    // Example: Abstract Class
    abstract class Language {
      abstract void method1();

      void method2() {
        System.out.println("This is a regular method");
      }
    }
    ```
2.  **Abstract Method:**

    * Abstract methods define a method signature without providing the implementation.
    * If a class has abstract methods, all its subclasses must implement these methods.

    ```java
    // Example: Abstract Method
    abstract void display();
    ```
3.  **Creating Subclasses:**

    * Subclasses can be created from abstract classes.
    * Members of the abstract class can be accessed using objects of the subclass.

    ```java
    // Example: Subclass and Accessing Members
    abstract class Language {
      public void display() {
        System.out.println("This is Java Programming");
      }
    }

    class Main extends Language {
      public static void main(String[] args) {
        Main obj = new Main();
        obj.display(); // Output: This is Java Programming
      }
    }
    ```
4.  **Implementing Abstract Methods:**

    * Subclasses must provide implementations for all abstract methods of the abstract superclass.

    <pre class="language-java"><code class="lang-java"><strong>// Example: Implementing Abstract Methods
    </strong>abstract class Animal {
      abstract void makeSound();

      public void eat() {
        System.out.println("I can eat.");
      }
    }

    class Dog extends Animal {
      public void makeSound() {
        System.out.println("Bark bark");
      }
    }
    </code></pre>
5.  **Accessing Abstract Class Constructors:**

    * Abstract classes can have constructors, and their constructors can be accessed using the `super` keyword in the subclass constructor.

    <pre class="language-java"><code class="lang-java"><strong>// Example: Accessing Abstract Class Constructors
    </strong>abstract class Animal {
      Animal() {
        // Constructor logic
      }
    }

    class Dog extends Animal {
      Dog() {
        super(); // Accessing abstract class constructor
        // Subclass constructor logic
      }
    }
    </code></pre>
6.  **Java Abstraction:**

    * Abstraction involves hiding unnecessary details and showing only essential information.
    * Abstract classes and methods are key to achieving abstraction in Java.

    ```java
    // Example: Java Abstraction
    abstract class MotorBike {
      abstract void brake();
    }

    class SportsBike extends MotorBike {
      public void brake() {
        System.out.println("SportsBike Brake");
      }
    }

    class MountainBike extends MotorBike {
      public void brake() {
        System.out.println("MountainBike Brake");
      }
    }
    ```
7. **Key Points:**
   * Use the `abstract` keyword for abstract classes and methods.
   * Abstract methods don't have implementations.
   * Abstract classes cannot be instantiated.
   * Subclasses inherit and provide implementations for abstract methods.
   * Constructors of abstract classes can be accessed using `super` in subclasses.
   * Abstraction helps manage complexity by focusing on high-level ideas.

