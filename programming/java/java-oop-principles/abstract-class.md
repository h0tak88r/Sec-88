# Abstract Class

###

###

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

