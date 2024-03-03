# Go Maps

A map maps keys to values.

```go
package main

import "fmt"

type Vertex struct {
	Lat, Long float64
}

var m map[string]Vertex

func main() {
	m = make(map[string]Vertex)
	m["Bell Labs"] = Vertex{
		40.68433, -74.39967,
	}
	fmt.Println(m["Bell Labs"]) //{40.68433 -74.39967}
}
```

### Map literals

```go
package main

import "fmt"

type Vertex struct {
	Lat, Long float64
}

var m = map[string]Vertex{
	"Bell Labs": Vertex{
		40.68433, -74.39967,
	},
	"Google": Vertex{
		37.42202, -122.08408,
	},
}

var n = map[string]Vertex{
	"Bell Labs": {40.68433, -74.39967},
	"Google":    {37.42202, -122.08408},
}

func main() {
	fmt.Println(m) // map[Bell Labs:{40.68433 -74.39967} Google:{37.42202 -122.08408}]
	fmt.Println(n) // map[Bell Labs:{40.68433 -74.39967} Google:{37.42202 -122.08408}]
}
```

### Mutating Maps

```go
package main

import "fmt"

func main() {
	m := make(map[string]int)
	
	m["Answer"] = 42
	fmt.Println("The value:", m["Answer"]) //The value: 42
	
	m["Answer"] = 48
	fmt.Println("The value:", m["Answer"])  // The value: 48
	
	delete(m, "Answer")
	fmt.Println("The value:", m["Answer"])  // The value: 0
	
	v, ok := m["Answer"]
	fmt.Println("The value:", v, "Present?", ok)  // The value: 0 Present? falsee
}
```
