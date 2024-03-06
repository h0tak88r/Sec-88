# Concurrency

### Goroutines

```go
// Goroutines
// A goroutine is a lightweight thread managed by the Go runtime.
// Example: go f(x, y, z) starts a new goroutine running f(x, y, z).

package main

import (
	"fmt"
	"time"
)

// Function to be executed in a goroutine
func say(s string) {
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		fmt.Println(s)
	}
}

func main() {
	go say("world") // Start a goroutine
	say("hello")    // Execution in the main goroutine
}
```

### Channels

```go
package main

import "fmt"

// sum calculates the sum of a slice of integers and sends the result to a channel
func sum(s []int, c chan int) {
	sum := 0
	for _, v := range s {
		sum += v
	}
	c <- sum // send sum to channel c
}

func main() {
	s := []int{7, 2, 8, -9, 4, 0}

	// Creating an integer channel
	c := make(chan int)

	// Start two goroutines to concurrently calculate partial sums
	go sum(s[:len(s)/2], c)
	go sum(s[len(s)/2:], c)

	// Receive partial sums from the channel
	x, y := <-c, <-c

	// Calculate the final sum
	result := x + y
	fmt.Println("Partial Sums:", x, y) // Partial Sums: -5 17
	fmt.Println("Final Result:", result) // Final Result: 12
}
```

### Range and Close

```go
package main

import (
	"fmt"
)

func fibonacci(n int, c chan int) {
	x, y := 0, 1
	for i := 0; i < n; i++ {
		c <- x // Send the current fibonacci number to the channel
		x, y = y, x+y
	}
	close(c) // Sender closes the channel to signal the end of sequence
}

func main() {
	// Create a channel with a buffer capacity of 10 (optional)
	c := make(chan int, 10)

	// Launch the fibonacci function as a goroutine
	go fibonacci(cap(c), c) // Pass the channel capacity to fibonacci

	// Use a range loop to receive and print fibonacci numbers
	for i := range c {
		fmt.Println(i)
	}
}
```
