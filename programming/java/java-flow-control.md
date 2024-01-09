# Java Flow Control

## Java if...else Statement

#### Working of if Statement

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-if-working.png" alt="if the number is greater than 0, code inside if block is executed, otherwise code inside if block is skipped" height="256" width="520"><figcaption><p>Working of Java if statement</p></figcaption></figure>

***

\
How the if...else statement works?

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-if-else-working.png" alt="If the condition is true, the code inside the if block is executed, otherwise, code inside the else block is executed" height="267" width="580"><figcaption><p>Working of Java if-else statements</p></figcaption></figure>

***

#### How the if...else...if ladder works?

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-if-else-if-statement.png" alt="If the first test condition if true, code inside first if block is executed, if the second condition is true, block inside second if is executed, and if all conditions are false, the else block is executed" height="312" width="740"><figcaption><p>Working of if...else...if ladder</p></figcaption></figure>

***

```java
class Main {
  public static void main(String[] args) {

    int number = 0;

    // checks if number is greater than 0
    if (number > 0) {
      System.out.println("The number is positive.");
    }

    // checks if number is less than 0
    else if (number < 0) {
      System.out.println("The number is negative.");
    }
    
    // if both condition is false
    else {
      System.out.println("The number is 0.");
    }
  }
}
```

\
\


**Output**

```
The number is 0.
```

### Java switch Statement

```java
switch (expression) {

  case value1:
    // code
    break;
  
  case value2:
    // code
    break;
  
  ...
  ...
  
  default:
    // default statements
  }
```

### Java for Loop

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-for-loop.png" alt="Working of for loop in Java with flowchart" height="493" width="320"><figcaption><p>Flowchart of Java for loop</p></figcaption></figure>

***

### for-each Loop Sytnax

```java
// print array elements 
class Main {
  public static void main(String[] args) {
    // create an array
    int[] numbers = {3, 9, 5, -5};
    // for each loop 
    for (int number: numbers) {
      System.out.println(number);
    }
  }
}

/* Output
3
9
5
-5
*/
```

### Java while loop

```java
while (testExpression) {
    // body of loop
}
```

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-while-loop.png" alt="Flowchart of while loop in Java" height="460" width="350"><figcaption><p>Flowchart of Java while loop</p></figcaption></figure>

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-do-while-loop.png" alt="Flowchart of do...while loop in Java" height="383" width="300"><figcaption><p>Flowchart of Java do while loop</p></figcaption></figure>

***

```java
do {
    // body of loop
} while(textExpression);
```

### Break Statement

### How break statement works?

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-break-statement-works.jpg" alt="How break statement works in Java programming?" height="354" width="560"><figcaption><p>Working of Java break Statement</p></figcaption></figure>

```java
if (number < 0.0) {
    break;
}
```

### Java break and Nested Loop

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/nested-while-loop-break.jpg" alt="The break statement terminates the innermost while loop in case of nested loops." height="238" width="300"><figcaption><p>Working of break Statement with Nested Loops</p></figcaption></figure>

### Labeled break Statement <a href="#labeled-break" id="labeled-break"></a>

\


<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/labeled-break-statement-Java.jpg" alt="The labeled break statement is used to break the outermost loop." height="276" width="350"><figcaption><p>Working of the labeled break statement in Java</p></figcaption></figure>

### Java continue Statement

**Working of Java continue statement**

<figure><img src="https://cdn.programiz.com/sites/tutorial2program/files/java-continue.png" alt="The working of continue statement with Java while, do...while, and for loop." height="499" width="560"><figcaption><p>Working of Java continue Statement</p></figcaption></figure>

**Java continue with Nested Loop**.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

***

### Java continue with Nested Loop <a href="#continue-nested-loops" id="continue-nested-loops"></a>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

### Labeled continue Statement <a href="#labeled-continue" id="labeled-continue"></a>

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>
