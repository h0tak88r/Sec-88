# Interface

1.  **Java Interface Overview:**

    An interface in Java is a fully abstract class that contains abstract methods. Interfaces are created using the `interface` keyword and cannot be instantiated. They provide a set of rules (abstract methods) that implementing classes must follow.

    ```java
    interface Language {
      public void getType();
      public void getVersion();
    }
    ```

    Here, `Language` is an interface with abstract methods `getType()` and `getVersion()`.
2.  **Implementing an Interface:**

    Like abstract classes, interfaces cannot be directly instantiated. Other classes must implement the interface using the `implements` keyword. An example demonstrates the implementation of an interface named `Polygon`.

    ```java
    interface Polygon {
      void getArea(int length, int breadth);
    }

    class Rectangle implements Polygon {
      public void getArea(int length, int breadth) {
        System.out.println("The area of the rectangle is " + (length * breadth));
      }
    }
    ```

    Output: `The area of the rectangle is 30`
3.  **Implementing Multiple Interfaces:**

    Java allows a class to implement multiple interfaces, providing flexibility in design.
4.  **Extending an Interface:**

    Interfaces can extend other interfaces using the `extends` keyword, creating a hierarchy of interfaces.

    ```java
    interface Line {
      // members of Line interface
    }

    // Extending interface
    interface Polygon extends Line {
      // members of Polygon interface
    }.
    ```
5.  **Default Methods in Interfaces:**

    Introduced in Java 8, default methods allow the addition of methods with implementation inside an interface. These methods are inherited like ordinary methods.

    ```java
    interface Polygon {
      void getArea();

      // Default method
      default void getSides() {
        System.out.println("I can get sides of a polygon.");
      }
    }
    ```

    Default methods help avoid issues when adding new methods to existing interfaces, as implementing classes automatically inherit the new method.
6.  **Private and Static Methods in Interface:**

    Java 8 introduced static methods inside an interface. With Java 9, private methods are also supported. Static methods can be accessed using the interface reference.

    ```java
    interface Polygon {
      static void staticMethod() { /* implementation */ }
    }

    // Accessing static method
    Polygon.staticMethod();
    ```
7.  **Practical Example of Interface:**

    A practical example illustrates the use of an interface named `Polygon` with a default method for calculating perimeter and an abstract method for calculating the area. The `Triangle` class implements the `Polygon` interface.

    ```java
    interface Polygon {
      void getArea();

      // Default method for calculating perimeter
      default void getPerimeter(int... sides) {
        int perimeter = 0;
        for (int side: sides) {
          perimeter += side;
        }
        System.out.println("Perimeter: " + perimeter);
      }
    }

    class Triangle implements Polygon {
      // Implementation of abstract method for calculating area
      public void getArea() {
        // ... calculation logic ...
        System.out.println("Area: " + area);
      }
    }
    ```

    Output:

    ```
    Area: 2.9047375096555625
    Perimeter: 9
    ```

    In this example, `Polygon` is an interface with a default method for perimeter calculation, and `Triangle` provides an implementation for the area calculation.
