# Encapsulation

Encapsulation is one of the key features of object-oriented programming. Encapsulation refers to the bundling of fields and methods inside a single class, It prevents outer classes from accessing and changing fields and methods of a class. This also helps to achieve **data hiding**.

**Example 1: Java Encapsulation**

```java
class Area {
  // Fields to calculate area
  int length;
  int breadth;

  // Constructor to initialize values
  Area(int length, int breadth) {
    this.length = length;
    this.breadth = breadth;
  }

  // Method to calculate area
  public void getArea() {
    int area = length * breadth;
    System.out.println("Area: " + area);
  }
}

class Main {
  public static void main(String[] args) {
    // Create object of Area, pass values of length and breadth
    Area rectangle = new Area(5, 6);
    rectangle.getArea();
  }
}
```

**Why Encapsulation?**

1. **Organization and Readability:**
   * Encapsulation helps organize related fields and methods within a class, improving code readability.
2. **Control over Data:**
   * It provides control over data values, allowing for logic implementation, such as in setter methods.
3. **Getter and Setter Methods:**
   * Getter and setter methods offer controlled access to class fields.
4. **Decoupling Components:**
   * Encapsulation supports the development of decoupled components, enabling independent testing and debugging.
5. **Data Hiding:**
   * Data hiding is achieved by making fields private, restricting unauthorized access from outside the class.

**Data Hiding Example:**

```java
class Person {
  // Private field
  private int age;

  // Getter method
  public int getAge() {
    return age;
  }

  // Setter method
  public void setAge(int age) {
    this.age = age;
  }
}

class Main {
  public static void main(String[] args) {
    // Create an object of Person
    Person p1 = new Person();

    // Change age using setter
    p1.setAge(24);

    // Access age using getter
    System.out.println("My age is " + p1.getAge());
  }
}
// Output:
// My age is 24
```

In the above example, we have a `private` field age. Since it is `private`, it cannot be accessed from outside the class.

In order to access age, we have used `public` methods: `getAge()` and `setAge()`. These methods are called getter and setter methods.

Making age private allowed us to restrict unauthorized access from outside the class. This is **data hiding**.

If we try to access the age field from the Main class, we will get an error.

```java
// error: age has private access in Person
p1.age = 24;
```
