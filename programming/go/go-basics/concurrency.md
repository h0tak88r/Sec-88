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

### mutexes

```go
// Visited tracks whether web pages have been visited.
// Its methods may be used concurrently from multiple goroutines.
type Visited struct {
    // Declare a mutex
    mu      sync.Mutex
    
    // Declare a map from URL (string) keys to integer values
    visited map[string]int
}

// VisitLink tracks that the page with the given URL has
// been visited, and returns the updated link count.
func (v *Visited) VisitLink(url string) int {
    // Locks the mutex
    v.mu.Lock()              
    
    // Ensures that the mutex is unlocked
    defer v.mu.Unlock()
    
    count := v.visited[url]
    count++
    
    // Updates the map
    v.visited[url] = count
    return count
}
```

> What are two potential problems with locking a mutex?

> It might block other goroutines that are also trying to lock the mutex; it could lead to deadlock.

### Event loops and goroutines

Wait Groupes

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

func main() {
	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Channel to communicate between the main goroutine and the event loop goroutine
	eventChannel := make(chan string)

	// Start the event loop in a separate goroutine
	go eventLoop(eventChannel, &wg)

	// Simulate some events by sending messages to the event loop
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go sendEvent(eventChannel, fmt.Sprintf("Event %d", i), &wg)
	}

	// Wait for all goroutines to finish before exiting the program
	wg.Wait()

	fmt.Println("All events processed. Exiting.")
}

// eventLoop is a goroutine that listens for events on the channel and processes them
func eventLoop(channel <-chan string, wg *sync.WaitGroup) {
	defer wg.Done() // Decrement the wait group when the goroutine is done

	for {
		// Receive events from the channel
		event, ok := <-channel

		// Check if the channel is closed
		if !ok {
			fmt.Println("Event loop closed. Exiting.")
			return
		}

		// Process the event
		fmt.Println("Processing event:", event)

		// Simulate some processing time
		time.Sleep(time.Second)

	}
}

// sendEvent simulates an external event by sending a message to the event loop
func sendEvent(channel chan<- string, event string, wg *sync.WaitGroup) {
	defer wg.Done() // Decrement the wait group when the goroutine is done

	// Send the event to the channel
	channel <- event

	// Simulate some processing time before sending the next event
	time.Sleep(time.Millisecond * 500)
}


```
