---
description: methods and intefaces in golang
---

# Methods and Interfaces

### Methods

a method is just a function with a receiver argument.

```go
type Vertex struct {
  X, Y float64
}

// Declaring Method with a truct type
func (v Vertex) Abs() float64 {
  return math.Sqrt(v.X * v.X + v.Y * v.Y)
}

v := Vertex{1, 2}
v.Abs() // Calling a Method
----------------------------------

// You can declare a method on non-struct types, too.
func (f MyFloat) Abs() float64 {
	if f < 0 {
		return float64(-f)
	}
	return float64(f)
}
------------------------------

// Mutation with Pointer receivers
// Scale scales the Vertex by a given factor. This method has a pointer receiver (*Vertex).
func (v *Vertex) Scale(f float64) {
	v.X = v.X * f
	v.Y = v.Y * f
}

v := Vertex{3, 4} // Initial Vertex: {X:3 Y:4}
v.Scale(10) // Vertex after scaling: {X:30 Y:40}
v.Abs() // Absolute value after scaling: 50
------------------

p := &v
p.Abs() // the method call p.Abs() is interpreted as (*p).Abs() 
```

### Interfaces

An _interface type_ is defined as a set of method signatures.

```go
package main

import (
	"fmt"
	"math"
)

// 1. Define an interface named Shaper with a single method Area().
type Shaper interface {
	Area() float64
}

// 2. Create a struct Circle that implements the Shaper interface.
type Circle struct {
	Radius float64
}

// 3. Implement the Area method for Circle.
func (c *Circle) Area() float64 {
	if c == nil {
		return 0
	}
	return math.Pi * c.Radius * c.Radius
}

// 4. Create a struct Rectangle that implements the Shaper interface.
type Rectangle struct {
	Width, Height float64
}

// 5. Implement the Area method for Rectangle.
func (r Rectangle) Area() float64 {
	return r.Width * r.Height
}

// 6. A function that takes any Shaper and prints its area.
func printArea(s Shaper) {
	if s == nil {
		fmt.Println("Area: 0")
	} else {
		fmt.Printf("Area: %v\n", s.Area())
	}
}

func main() {
	// 7. Create instances of Circle and Rectangle.
	circle := Circle{Radius: 5}
	rectangle := Rectangle{Width: 3, Height: 4}

	// 8. Call the printArea function with Circle and Rectangle instances.
	printArea(&circle)    // Outputs: Area: 78.53981633974483
	printArea(rectangle)  // Outputs: Area: 12
	printArea(nil)       // Outputs: Area: 0

	// 9. Interface values with nil underlying values.
	var nilCircle *Circle
	var i Shaper
	i = nilCircle
	describe(i)          // Outputs: Nil Circle: <nil>, Type: *main.Circle
	printArea(nilCircle) // Outputs: Area: 0

	// 10. The empty interface allows holding values of any type.
	var emptyInterface interface{}
	describe(emptyInterface) // Outputs: (nil, <nil>)

	emptyInterface = 42
	describe(emptyInterface) // Outputs: (42, int)

	emptyInterface = "hello"
	describe(emptyInterface) // Outputs: (hello, string)
}

// 11. A function that describes an interface value.
func describe(i interface{}) {
	fmt.Printf("(%v, %T)\n", i, i)
}
```

### Type Assertions:

```go
package main

import "fmt"

func main() {
	var i interface{} = "hello"

	// Type assertion: Assigns the underlying string value to variable s.
	s := i.(string)
	fmt.Println(s) // Outputs: hello

	// Type assertion with a boolean check.
	s, ok := i.(string)
	fmt.Println(s, ok) // Outputs: hello true

	// Type assertion with a non-matching type, no panic, ok is false, and f is the zero value of float64.
	f, ok := i.(float64)
	fmt.Println(f, ok) // Outputs: 0 false

	// Type assertion with a non-matching type, triggers a panic.
	// f = i.(float64)
	// fmt.Println(f)
}
```

### Type Switches:

```go
package main

import "fmt"

func do(i interface{}) {
	switch v := i.(type) {
	case int:
		fmt.Printf("Twice %v is %v\n", v, v*2)
	case string:
		fmt.Printf("%q is %v bytes long\n", v, len(v))
	default:
		fmt.Printf("I don't know about type %T!\n", v)
	}
}

func main() {
	do(21)        // Outputs: Twice 21 is 42
	do("hello")   // Outputs: "hello" is 5 bytes long
	do(true)      // Outputs: I don't know about type bool!
}
```

### Stringers:

```go
package main

import "fmt"

// Person is a struct with Name and Age fields.
type Person struct {
	Name string
	Age  int
}

// String method for Person, implementing the Stringer interface.
func (p Person) String() string {
	return fmt.Sprintf("%v (%v years)", p.Name, p.Age)
}

func main() {
	// Creating instances of Person.
	a := Person{"Arthur Dent", 42}
	z := Person{"Zaphod Beeblebrox", 9001}

	// Using Stringer interface in fmt.Println.
	fmt.Println(a, z)
	// Outputs: Arthur Dent (42 years) Zaphod Beeblebrox (9001 years)
}
```

### Errors

```go
package main

import (
	"fmt"
	"math"
)

// ErrNegativeSqrt is a custom error type for negative square roots.
type ErrNegativeSqrt float64

// Error method for ErrNegativeSqrt.
func (e ErrNegativeSqrt) Error() string {
	return fmt.Sprintf("cannot Sqrt negative number: %v", float64(e))
}

// Sqrt calculates the square root of a number and returns an error for negative input.
func Sqrt(x float64) (float64, error) {
	if x < 0 {
		return 0, ErrNegativeSqrt(x)
	}
	return math.Sqrt(x), nil
}

func main() {
	// Example usage:
	result, err := Sqrt(9)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Square root:", result)
	}

	result, err = Sqrt(-2)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Square root:", result)
	}
}
```

### Readers

```go
package main

import (
	"fmt"
	"io"
	"strings"
)

func main() {
	// Create a strings.Reader with the input "Hello, Reader!"
	r := strings.NewReader("Hello, Reader!")

	// Create a byte slice of size 8 to read data into.
	b := make([]byte, 8)

	// Loop to read data from the strings.Reader in chunks of 8 bytes.
	for {
		// Read data into the byte slice.
		n, err := r.Read(b)

		// Print the number of bytes read, the error, and the content of the byte slice.
		fmt.Printf("n = %v err = %v b = %v\n", n, err, b)
		fmt.Printf("b[:n] = %q\n", b[:n])

		// Break the loop if we've reached the end of the stream (io.EOF).
		if err == io.EOF {
			break
		}
	}
}

```

