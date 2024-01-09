# Java Essentials Code Notes

```java
import java.util.Scanner;

public class HelloJava {
    public static void main(String[] args) {
        // Printing
        System.out.println("Hello World !!\nNew Line !!");

        // Variables
        int score = 6; // Declare and Initialize
        score = score + 1; // Update variable
        System.out.println("Your score: " + score); // Your score: 7

        double studentGrade = 88.8;
        String name = "Mosaad Sallam";
        System.out.println(name + " : " + studentGrade); // Mosaad Sallam : 88.8

        long views = 3_000_000_000L;
        float price = 50.99F;
        char answer = 'A';
        boolean isRaised = false;
        double result = 10 % 3; // 1

        int x = 1, y;
        y = ++x; // Postfix x=2 y=2 Score
        x += 2; // x = x + 2

        // Casting in JAVA
        long a = 5;
        int b = (int) a;
        System.out.println(b); // 5

        // Salary Program
        String salaryDetails =
                "Salary details :" +
                        "\n------------------" +
                        "\nYour base salary : " + a +
                        "\nTaxes : " + b +
                        "\nSalary after taxes : " + (x - y) +
                        "\nIncentive : " + score +
                        "\n--------------------" +
                        "\nNet salary : " + price;
        System.out.println(salaryDetails);

        // If-else Statement
        int number1 = 1;
        if (number1 > 0) {
            System.out.println("The number is positive.");
        } else {
            System.out.println("The number is not positive.");
        }
        System.out.println("Statement outside if...else block");

        // Operators
        // Arithmetic Operators
        int e = 12, f = 5;
        System.out.println("a + b = " + (e + f));
        System.out.println("a - b = " + (e - f));
        System.out.println("a * b = " + (e * f));
        System.out.println("a / b = " + (e / f));
        System.out.println("a % b = " + (e % f));

        // Assignment Operators
        int g = 4, lol;
        lol = g;
        System.out.println("Var using =: " + lol);
        lol += g;
        System.out.println("Var using +=: " + lol);
        lol *= g;
        System.out.println("Var using *=: " + lol);

        // Relational Operators
        int h = 7, j = 11;
        System.out.println("a is " + a + " and b is " + b);
        System.out.println(h == j); // false
        System.out.println(h != j); // true
        System.out.println(h > j);  // false
        System.out.println(h < j);  // true
        System.out.println(h >= j);  // false
        System.out.println(h <= j);  // true

        // Logical Operators
        System.out.println((5 > 3) && (8 > 5)); // true
        System.out.println((5 > 3) && (8 < 5)); // false
        System.out.println((5 < 3) || (8 > 5)); // true
        System.out.println((5 > 3) || (8 < 5)); // true
        System.out.println((5 < 3) || (8 < 5)); // false
        System.out.println(!(5 == 3)); // true
        System.out.println(!(5 > 3)); // false

        // Unary Operators
        int l = 12, z = 12;
        int result1, result2;
        System.out.println("Value of a: " + l);
        result1 = ++l;
        System.out.println("After increment: " + result1);
        System.out.println("Value of b: " + z);
        result2 = --z;
        System.out.println("After decrement: " + result2);

        // Java instanceof Operator
        String str = "Programiz";
        boolean isString;
        isString = str instanceof String;
        System.out.println("Is str an object of String? " + isString);

        // switch-case
        int num = 44;
        String size;
        switch (num) {
            case 29:
                size = "Small";
                break;
            case 42:
                size = "Medium";
                break;
            case 44:
                size = "Large";
                break;
            case 48:
                size = "Extra Large";
                break;
            default:
                size = "Unknown";
                break;
        }
        System.out.println("Size: " + size);

        // Getting Input
        Scanner input = new Scanner(System.in);
        System.out.print("Enter float: ");
        float myFloat = input.nextFloat();
        System.out.println("Float entered = " + myFloat);
        System.out.print("Enter double: ");
        double myDouble = input.nextDouble();
        System.out.println("Double entered = " + myDouble);
        System.out.print("Enter text: ");
        String myString = input.next();
        System.out.println("Text entered = " + myString);

        // Java Arrays
        String[] array = new String[100];
        double[] data;
        data = new double[10];
        double[] dataArray = new double[10];
        int[] ageArray = {12, 4, 5, 2, 5};  // Declare, Initialize, and Access
        System.out.println("Accessing Elements of Array:");
        for (int i = 0; i < ageArray.length; i++) {
            System.out.println("Element at index " + i + ": " + ageArray[i]);
        }

        // Compute Sum and Average of Array Elements
        int[] numbersArray = {2, -9, 0, 5, 12, -25, 22, 9, 8, 12};
        int sumArray = 0;
        double averageArray;
        for (int numArray : numbersArray) {
            sumArray += numArray;
        }
        int arrayLength = numbersArray.length;
        averageArray = ((double) sumArray / arrayLength);
        System.out.println("Sum = " + sumArray); // Sum = 36
        System.out.println("Average = " + averageArray); // Average = 3.6

        // Create a 2D array
        int[][] array2D = {
                {1, 2, 3},
                {4, 5, 6, 9},
                {7},
        };
        System.out.println("Length of row 1: " + array2D[0].length);
        System.out.println("Length of row 2: " + array2D[1].length);
        System.out.println("Length of row 3: " + array2D[2].length);

        // Copying arrays
        int[] numbersCopy = {1, 2, 3, 4, 5, 6};
        int[] positiveNumbers = numbersCopy.clone(); // Copying arrays
        for (int numCopy : positiveNumbers) {
            System.out.print(numCopy + ", ");
        }
    }
}
```
