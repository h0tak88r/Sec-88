# Method Overriding

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
