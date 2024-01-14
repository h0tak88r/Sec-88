# Exception Handling

**Exception Handling**: Dealing with unexpected events during program execution.

```java
// Exception Handling: Dealing with unexpected events during program execution.

class ExceptionHandling {
    public static void main(String[] args) {
        try {
            // Code that might generate an exception
            int result = divideNumbers(10, 0);
            System.out.println("Result: " + result);  // This line won't be executed in case of an exception
        } catch (ArithmeticException e) {
            // Handling the specific exception (ArithmeticException)
            System.out.println("Exception caught: " + e.getMessage());
        } finally {
            // Code inside finally block always executes, whether there's an exception or not
            System.out.println("Finally block executed");
        }

        // Code continues to execute after handling the exception
        System.out.println("Program continues...");
    }

    // A method that might throw an exception
    static int divideNumbers(int numerator, int denominator) {
        // Check if the denominator is 0 before performing the division
        if (denominator == 0) {
            // Throw an ArithmeticException with a custom message
            throw new ArithmeticException("Cannot divide by zero");
        }
        return numerator / denominator;
    }
}

```
