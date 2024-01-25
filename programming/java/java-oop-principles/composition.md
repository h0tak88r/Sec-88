# Composition

In Java, composition is a design principle that allows you to create complex objects by combining simpler objects or types. It is a way to achieve code reuse without using inheritance. Composition involves creating relationships between classes by having one class contain an instance of another class. This is in contrast to inheritance, where a class can inherit properties and behaviors from another class.

Here's a simple example to illustrate composition in Java:

```java
// Simple class representing an Engine
class Engine {
    public void start() {
        System.out.println("Engine started");
    }
}

// Class representing a Car that uses composition to include an Engine
class Car {
    private Engine engine;

    public Car(Engine engine) {
        this.engine = engine;
    }

    public void start() {
        System.out.println("Car is starting");
        engine.start();
    }
}

public class CompositionExample {
    public static void main(String[] args) {
        // Create an Engine instance
        Engine carEngine = new Engine();

        // Create a Car instance, passing the Engine instance through the constructor
        Car myCar = new Car(carEngine);

        // Start the car, which internally starts the engine
        myCar.start();
    }
}
```

In this example:

* The `Engine` class has a method `start()` that prints a message indicating the engine is starting.
* The `Car` class has a composition relationship with the `Engine` class. It contains an instance of the `Engine` class as a private member variable.
* The `Car` class also has a method `start()`, which, in addition to printing a message for the car starting, delegates the task of starting the engine to the `Engine` instance.

By using composition, you can create modular and flexible code. If you later need to change the behavior of the `Engine` class, it won't affect the `Car` class as long as the interface between them remains the same. This is in contrast to inheritance, where changes to a superclass can potentially affect all subclasses.

## Example 2

Credits: [https://www.geeksforgeeks.org/composition-in-java/](https://www.geeksforgeeks.org/composition-in-java/)

```
// Java program to Illustrate Concept of Composition

// Importing required classes
import java.io.*;
import java.util.*;

// Class 1
// Helper class
// Book class
class Book {

	// Member variables of this class
	public String title;
	public String author;

	// Constructor of this class
	Book(String title, String author)
	{

		// This keyword refers top current instance
		this.title = title;
		this.author = author;
	}
}

// Class 2
// Helper class
// Library class contains list of books.
class Library {

	// Reference to refer to list of books.
	private final List<Book> books;

	// Constructor of this class
	Library(List<Book> books)
	{

		// This keyword refers to current instance itself
		this.books = books;
	}

	// Method of this class
	// Getting the list of books
	public List<Book> getListOfBooksInLibrary()
	{
		return books;
	}
}

// Class 3
// Main class
class GFG {

	// Main driver method
	public static void main(String[] args)
	{

		// Creating the objects of class 1 (Book class)
		// inside main() method
		Book b1
			= new Book("EffectiveJ Java", "Joshua Bloch");
		Book b2
			= new Book("Thinking in Java", "Bruce Eckel");
		Book b3 = new Book("Java: The Complete Reference",
						"Herbert Schildt");

		// Creating the list which contains the
		// no. of books.
		List<Book> book = new ArrayList<Book>();

		// Adding books to List object
		// using standard add() method
		book.add(b1);
		book.add(b2);
		book.add(b3);

		// Creating an object of class 2
		Library library = new Library(book);

		// Calling method of class 2 and storing list of
		// books in List Here List is declared of type
		// Books(user-defined)
		List<Book> books
			= library.getListOfBooksInLibrary();

		// Iterating over for each loop
		for (Book bk : books) {

			// Print and display the title and author of
			// books inside List object
			System.out.println("Title : " + bk.title
							+ " and "
							+ " Author : " + bk.author);
		}
	}
}

```
