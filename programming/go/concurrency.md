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

import (
	"fmt"
	"time"
)

func main() {

	// Loop that runs 5 Sleepy gophers go routines
	c := make(chan int)
	for i := 0; i < 5; i++ {
		go sleepyGopher(i, c)
	}

	// Loop Receives Gopher id
	for i := 0; i < 5; i++ {
		gopherId := <-c
		fmt.Println("gopher ", gopherId, " has Finished Sleeping")
	}
}

// sleepy Gopher Sends id when finish sleeping
func sleepyGopher(id int, c chan int) {
	time.Sleep(5 * time.Second)
	fmt.Println("......", id, " snore.....")
	c <- id
}
```

### Select

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// Loop that runs 5 Sleepy gophers go routines
	c := make(chan int)
	for i := 0; i < 5; i++ {
		go sleepyGopher(i, c)
	}

	timeOut := time.After(3 * time.Second)
	for i := 0; i < 5; i++ {
		// select acts lke switches it keeps waiting for the two cases
		select {
		case id := <-c:
			fmt.Print("gopher ", id, " has finished")
		case <-timeOut:
			fmt.Println("my patience ran out")
			return
		}
	}
}

// sleepy goher sleeps for 5 seconds
func sleepyGopher(id int, c chan int) {
	time.Sleep(5 * time.Second)
	fmt.Println("......", id, " snore.....")
	c <- id
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

	// Launch the fibonacci function as a goroutineblob:file:///a9674d55-dac3-43f9-9743-4a7c48bb3063﻿﻿
	go fibonacci(cap(c), c) // Pass the channel capacity to fibonacci

	// Use a range loop to receive and print fibonacci numbers
	for i := range c {
		fmt.Println(i)
	}
}
```

### mutex

To prevent data races, we'll use a mutex to synchronize access to this shared resource.

```go
package main

import (
	"fmt"
	"sync"
)

var (
	sharedResource int // Shared resource accessed by workers
	mutex          sync.Mutex // Mutex to synchronize access to sharedResource
)

// worker is a function that performs some work.
// It takes a waitgroup as a parameter to signal when it's done.
func worker(id int, wg *sync.WaitGroup) {
	defer wg.Done() // Signal that this worker is done when the function exits
	for i := 0; i < 10; i++ {
		fmt.Printf("Worker %d starting\n", id)
		
		// Lock the mutex before accessing the shared resource
		mutex.Lock()
		sharedResource++
		// Perform the work here, using the shared resource
		// This is just a placeholder, you can replace it with the actual work
		fmt.Printf("Worker %d incremented shared resource to: %d\n", id, sharedResource)
		mutex.Unlock() // Unlock the mutex after accessing the shared resource

		fmt.Printf("Worker %d done\n", id)
	}
}

func main() {
	var wg sync.WaitGroup // Create a new waitgroup
	wg.Add(1)             // Add 1 to the waitgroup to indicate that we're waiting for 1 worker
	go worker(1, &wg)        // Start the worker goroutine

	wg.Wait() // Wait until all workers are done
}
```

> What are two potential problems with locking a mutex?

> It might block other goroutines that are also trying to lock the mutex; it could lead to deadlock.

### Event loops and go-routines

### Wait Groups

```go
package main

import (
	"fmt"
	"sync"
)

// worker is a function that performs some work.
// It takes a waitgroup as a parameter to signal when it's done.
func worker(wg *sync.WaitGroup) {
	defer wg.Done() // Signal that this worker is done when the function exits
	for i := 0; i < 10; i++ {
		fmt.Printf("Worker %d starting\n", i)
		// Perform the work here
		fmt.Printf("Worker %d done\n", i)
	}
}

func main() {
	var wg sync.WaitGroup // Create a new waitgroup
	wg.Add(1)             // Add 1 to the waitgroup to indicate that we're waiting for 1 worker
	go worker(&wg)        // Start the worker goroutine

	wg.Wait() // Wait until all workers are done
}
```
