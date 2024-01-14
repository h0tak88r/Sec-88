# Inheritance

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
