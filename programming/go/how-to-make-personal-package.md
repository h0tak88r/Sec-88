# How to make personal Package

```go
// Package mypackage provides functionality related to something.
package mypackage

import (
    "errors"
)

// MyStruct represents a structure for some functionality.
type MyStruct struct {
    // Define fields here
    field1 string
    field2 int
}

// NewMyStruct is a constructor function that initializes and returns a new instance of MyStruct.
func NewMyStruct(field1 string, field2 int) *MyStruct {
    return &MyStruct{
        field1: field1,
        field2: field2,
    }
}

// Method1 is a method associated with MyStruct.
func (m *MyStruct) Method1() {
    // Method implementation here
}

// Method2 is another method associated with MyStruct.
func (m *MyStruct) Method2() {
    // Method implementation here
}

// FunctionExample is an example of a standalone function in the package.
func FunctionExample() {
    // Function implementation here
}
```

Use package in other code

```go
package main

import (
    "fmt"
    "your_module_path/mypackage" // Import the package
)

func main() {
    // Create an instance of MyStruct using the constructor function
    myInstance := mypackage.NewMyStruct("Hello", 42)

    // Call methods on the instance
    myInstance.Method1()
    myInstance.Method2()

    // Call the standalone function from the package
    mypackage.FunctionExample()
}
```
