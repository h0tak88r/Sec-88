# regexp Packages

```go
package main

import (
    "bytes"
    "fmt"
    "regexp"
)

func main() {
    // Check if the pattern matches the string "peach"
    match, _ := regexp.MatchString("p([a-z]+)ch", "peach")
    fmt.Println(match)

    // Compile the regular expression pattern
    r, _ := regexp.Compile("p([a-z]+)ch")

    // Check if the compiled pattern matches the string "peach"
    fmt.Println(r.MatchString("peach"))

    // Find the first match of the pattern in the string "peach punch"
    fmt.Println(r.FindString("peach punch"))

    // Find the start and end indices of the first match in the string "peach punch"
    fmt.Println("idx:", r.FindStringIndex("peach punch"))

    // Find the submatches of the first match in the string "peach punch"
    fmt.Println(r.FindStringSubmatch("peach punch"))

    // Find the start and end indices of submatches in the string "peach punch"
    fmt.Println(r.FindStringSubmatchIndex("peach punch"))

    // Find all matches of the pattern in the string "peach punch pinch"
    fmt.Println(r.FindAllString("peach punch pinch", -1))

    // Find all submatches and their indices in the string "peach punch pinch"
    fmt.Println("all:", r.FindAllStringSubmatchIndex(
        "peach punch pinch", -1))

    // Find the first 2 matches of the pattern in the string "peach punch pinch"
    fmt.Println(r.FindAllString("peach punch pinch", 2))

    // Check if the pattern matches the byte slice "peach"
    fmt.Println(r.Match([]byte("peach")))

    // MustCompile panics if the expression cannot be parsed
    r = regexp.MustCompile("p([a-z]+)ch")
    fmt.Println("regexp:", r)

    // Replace all matches of the pattern with "<fruit>" in the string "a peach"
    fmt.Println(r.ReplaceAllString("a peach", "<fruit>"))

    // Replace all matches of the pattern in the byte slice "a peach" with uppercase letters
    in := []byte("a peach")
    out := r.ReplaceAllFunc(in, bytes.ToUpper)
    fmt.Println(string(out))
}
```

```go
$ go run regular-expressions.go
true
true
peach
idx: [0 5]
[peach ea]
[0 5 1 3]
[peach punch pinch]
all: [[0 5 1 3] [6 11 7 9] [12 17 13 15]]
[peach punch]
true
regexp: p([a-z]+)ch
a <fruit>
a PEACH
```
