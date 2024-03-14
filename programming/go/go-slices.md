# Go Slices

### Slices are like references to arrays

A slice does not store any data, it just describes a section of an underlying array. Changing the elements of a slice modifies the corresponding elements of its underlying array. Other slices that share the same underlying array will see those changes.

```go
package main

import "fmt"

func main() {
	names := [4]string{
		"John",
		"Paul",
		"George",
		"Ringo",
	}
	fmt.Println(names)  // [John Paul George Ringo]
	a := names[0:2]
	b := names[1:3]
	fmt.Println(a, b)  // [John Paul] [Paul George]
	b[0] = "XXX"
	fmt.Println(a, b)  // [John XXX] [XXX George]
	fmt.Println(names) // [John XXX George Ringo]
}
```

Notice Paul the 0 in names array ,the 0 in b slice the, the 1 in a slice changed in all of them

### Slice literals

A slice literal is like an array literal without the length. This is an array literal:

```go
[3]bool{true, true, false}
```

And this creates the same array as above, then builds a slice that references it:

```go
[]bool{true, true, false}
```

_**Example**_

```go
package main

import "fmt"

func main() {
	q := []int{2, 3, 5, 7, 11, 13}
	fmt.Println(q) // [2 3 5 7 11 13]

	r := []bool{true, false, true, true, false, true}
	fmt.Println(r) // [true false true true false true]

	s := []struct {
		i int
		b bool
	}{
		{2, true},
		{3, false},
		{5, true},
		{7, true},
		{11, false},
		{13, true},
	}
	fmt.Println(s)  // [{2 true} {3 false} {5 true} {7 true} {11 false} {13 true}]
}
```

### Slice length and capacity

```go
package main

import "fmt"

func main() {
	s := []int{2, 3, 5, 7, 11, 13}
	printSlice(s) // len=6 cap=6 [2 3 5 7 11 13]

	// Slice the slice to give it zero length.
	s = s[:0]
	printSlice(s) // len=0 cap=6 []

	// Extend its length.
	s = s[:4]
	printSlice(s) // len=4 cap=6 [2 3 5 7]

	// Drop its first two values.
	s = s[2:]
	printSlice(s) // len=2 cap=4 [5 7]
}

func printSlice(s []int) {
	fmt.Printf("len=%d cap=%d %v\n", len(s), cap(s), s)
}

```

### Creating a slice with make

```go
package main

import "fmt"

func main() {
	a := make([]int, 5)
	printSlice("a", a) // a len=5 cap=5 [0 0 0 0 0]

	b := make([]int, 0, 5)
	printSlice("b", b) // b len=0 cap=5 []

	c := b[:2]
	printSlice("c", c) // c len=2 cap=5 [0 0]

	d := c[2:5]
	printSlice("d", d) // d len=3 cap=3 [0 0 0]
}

func printSlice(s string, x []int) {
	fmt.Printf("%s len=%d cap=%d %v\n",
		s, len(x), cap(x), x)
}
```

### Slices of slices

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	// Create a tic-tac-toe board.
	board := [][]string{
		[]string{"_", "_", "_"},
		[]string{"_", "_", "_"},
		[]string{"_", "_", "_"},
	}
	// The players take turns.
	board[0][0] = "X"
	board[2][2] = "O"
	board[1][2] = "X"
	board[1][0] = "O"
	board[0][2] = "X"
	
	for i := 0; i < len(board); i++ {
		fmt.Printf("%s\n", strings.Join(board[i], " "))
	}
}
------------
Output:
X _ X
O _ X
_ _ O
```

### Appending to a slice

```go
package main

import "fmt"

func main() {
	var s []int
	printSlice(s)  // len=0 cap=0 []

	// append works on nil slices.
	s = append(s, 0)
	printSlice(s)  // len=1 cap=1 [0]

	// The slice grows as needed.
	s = append(s, 1)
	printSlice(s)  // len=2 cap=2 [0 1]

	// We can add more than one element at a time.
	s = append(s, 2, 3, 4)
	printSlice(s)  // len=5 cap=6 [0 1 2 3 4]
}

func printSlice(s []int) {
	fmt.Printf("len=%d cap=%d %v\n", len(s), cap(s), s)
}
```

### Range

```go
package main
import "fmt"
var pow = []int{1, 2, 4, 8, 16, 32, 64, 128}

func main() {
	for i, v := range pow {
		fmt.Printf("2**%d = %d\n", i, v)
	}
}
// When ranging over a slice, two values are returned for each iteration. The first is the index, and the second is a copy of the element at that index. 
// Output
2**0 = 1
2**1 = 2
2**2 = 4
2**3 = 8
2**4 = 16
2**5 = 32
2**6 = 64
2**7 = 128
---------------------------------------------------------------
// You can skip the index or value by assigning to `_`.
for i, _ := range pow OR for i := range pow
for _, value := range pow
```
