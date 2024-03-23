---
description: https://blog.jetbrains.com/go/2022/11/22/comprehensive-guide-to-testing-in-go
---

# Unit Testing

### How to do unit testing

* Create file `project_test.go`
* The test function signature is `TestXXX(t *testing.T)`

Those two steps are the only mandatory step to create unit testing. But we can follow some best practices to structure our tests and test cases:

* Structure our test as test tables with many test cases
* Properly assert the function behavior
* Name test cases as descriptive as possible

### Useful Commands

* Use `go test -race ./...` to run the unit test with a check for a race condition
* Use `go tool cover -func=coverage.out` to display coverage information on the terminal console
* Use `go tool cover -html=coverage.out` to display the coverage information on HTML format in browser.

### Examples

```go
package main

import "strconv"

// If the number is divisible by 3, write "Foo" otherwise, the number
func Fooer(input int) string {

    isfoo := (input % 3) == 0

    if isfoo {
        return "Foo"
    }

    return strconv.Itoa(input)
}
```

**project\_test.go**

```go
package main
import "testing"
func TestFooer(t *testing.T) {
    result := Fooer(3)
    if result != "Foo" {
    t.Errorf("Result was incorrect, got: %s, want: %s.", result, "Foo")
    }
}
```

### Table Driven testing

```go
func TestFooerTableDriven(t *testing.T) {
      // Defining the columns of the table
        var tests = []struct {
        name string
            input int
            want  string
        }{
            // the table itself
            {"9 should be Foo", 9, "Foo"},
            {"3 should be Foo", 3, "Foo"},
            {"1 is not Foo", 1, "1"},
            {"0 should be Foo", 0, "Foo"},
        }
      // The execution loop
        for _, tt := range tests {
            t.Run(tt.name, func(t *testing.T) {
                ans := Fooer(tt.input)
                if ans != tt.want {
                    t.Errorf("got %s, want %s", ans, tt.want)
                }
            })
        }
    }
```

#### Errors and Logs <a href="#errors-and-logs" id="errors-and-logs"></a>

```go
func TestFooer2(t *testing.T) {
            input := 3
            result := Fooer(3)
            t.Logf("The input was %d", input)
            if result != "Foo" {
                t.Errorf("Result was incorrect, got: %s, want: %s.", result, "Foo")
            }
            t.Fatalf("Stop the test now, we have seen enough")
            t.Error("This won't be executed")
        }
```

#### Running Parallel Tests <a href="#running-parallel-tests" id="running-parallel-tests"></a>

The following code will test `Fooer(3)` and `Fooer(7)` at the same time

```go
func TestFooerParallel(t *testing.T) {
        t.Run("Test 3 in Parallel", func(t *testing.T) {
            t.Parallel()
            result := Fooer(3)
            if result != "Foo" {
                t.Errorf("Result was incorrect, got: %s, want: %s.", result, "Foo")
            }
        })
        t.Run("Test 7 in Parallel", func(t *testing.T) {
            t.Parallel()
            result := Fooer(7)
            if result != "7" {
                t.Errorf("Result was incorrect, got: %s, want: %s.", result, "7")
            }
        })
    }
```

#### Skipping Tests <a href="#skipping-tests" id="skipping-tests"></a>

```go
func TestFooerSkiped(t *testing.T) {
        if testing.Short() {
            t.Skip("skipping test in short mode.")
        }
        result := Fooer(3)
        if result != "Foo" {
            t.Errorf("Result was incorrect, got: %s, want: %s.", result, "Foo")
        }
    }
```

