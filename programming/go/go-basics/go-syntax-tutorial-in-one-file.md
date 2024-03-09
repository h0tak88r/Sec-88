# Go Syntax Tutorial in one file

```go
package main

import "fmt"

// Function to add two numbers
func add(a, b int) int {
	return a + b
}

func main() {
	// Hello World
	fmt.Println("Hello, World!")

	// Values and Variables
	var im, jm int = 1, 2
	km := 3
	cm, python, java := true, false, "no!"
	var num int = 42
	fmt.Println(im, jm, km, cm, python, java)
	fmt.Println("Value of num:", num)

	// Constants
	const pi float64 = 3.14
	fmt.Println("Value of pi:", pi)

	// For loop
	fmt.Println("\nFor Loop:")
	for i := 0; i < 5; i++ {
		fmt.Println(i)
	}
	
	// The init and post statements are optional.
	sum := 1
	for ; sum < 1000; {
		sum += sum
	}
	fmt.Println(sum)
	
	// while loop in Go
	for sum < 1000 {
		sum += sum
	}
	fmt.Println(sum)
	
	// Infinite Loop
	for {
	}
	
	// If/Else
	fmt.Println("\nIf/Else:")
	x := 10
	if x > 5 {
		fmt.Println("x is greater than 5")
	} else {
		fmt.Println("x is less than or equal to 5")
	}

	// Switch
	fmt.Println("\nSwitch:")
	day := "Monday"
	switch day {
	case "Monday":
		fmt.Println("It's Monday!")
	case "Tuesday":
		fmt.Println("It's Tuesday!")
	default:
		fmt.Println("It's another day.")
	}

	// Arrays
	fmt.Println("\nArrays:")
	var arr [3]int
	arr[0] = 1
	arr[1] = 2
	arr[2] = 3
	fmt.Println("Array:", arr)

	// Slices
	fmt.Println("\nSlices:")
	slice := arr[1:3]
	fmt.Println("Slice:", slice)

	// Maps
	fmt.Println("\nMaps:")
	person := map[string]string{
		"name":  "John",
		"age":   "25",
		"city":  "New York",
	}
	fmt.Println("Person:", person)

	// Range
	fmt.Println("\nRange:")
	numbers := []int{1, 2, 3, 4, 5}
	for index, value := range numbers {
		fmt.Printf("Index: %d, Value: %d\n", index, value)
	}

	// Functions
	fmt.Println("\nFunctions:")
	result := add(3, 4)
	fmt.Println("Result of add function:", result)

	// Defer
	fmt.Println("\nDefer:")
	deferExample()

	// Pointers
	fmt.Println("\nPointers:")
	pointerExample()

	// Structs
	fmt.Println("\nStructs:")
	structExample()

	// Interfaces
	fmt.Println("\nInterfaces:")
	interfaceExample()

	// Goroutines
	fmt.Println("\nGoroutines:")
	goroutineExample()

	// Channels
	fmt.Println("\nChannels:")
	channelExample()
}

// Defer
func deferExample() {
	defer fmt.Println("Deferred statement executed after the function returns.")
	fmt.Println("Regular statement.")
}

// Pointers
func pointerExample() {
	num := 10
	ptr := &num
	fmt.Println("Value of num:", num)
	fmt.Println("Address of num:", &num)
	fmt.Println("Value through pointer:", *ptr)
}

// Structs
type personStruct struct {
	Name string
	Age  int
}

func structExample() {
	person := personStruct{"Alice", 30}
	fmt.Println("Person:", person)
}

// Interfaces
type animal interface {
	Sound() string
}

type dog struct{}

func (d dog) Sound() string {
	return "Woof!"
}

type cat struct{}

func (c cat) Sound() string {
	return "Meow!"
}

func interfaceExample() {
	var myPet animal
	myPet = dog{}
	fmt.Println("Dog says:", myPet.Sound())
	myPet = cat{}
	fmt.Println("Cat says:", myPet.Sound())
}

// Goroutines
func goroutineExample() {
	go func() {
		fmt.Println("Goroutine executed concurrently.")
	}()
	fmt.Println("Main function continues to run.")
}

// Channels
func channelExample() {
	ch := make(chan string)
	go func() {
		ch <- "Hello from channel!"
	}()
	msg := <-ch
	fmt.Println("Received message:", msg)
}

```
