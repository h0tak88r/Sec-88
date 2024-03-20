---
description: https://pkg.go.dev/bufio
---

# bufio



1. **Reading from a file using bufio.Reader**:

```go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    // Open the file
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer file.Close()

    // Create a bufio.Reader
    reader := bufio.NewReader(file)

    // Read data from the file
    data := make([]byte, 100) // Read up to 100 bytes
    bytesRead, err := reader.Read(data)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    fmt.Printf("Read %d bytes: %s\n", bytesRead, data[:bytesRead])
}
```

2. **Writing to a file using bufio.Writer**:

```go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    // Open the file
    file, err := os.Create("output.txt")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer file.Close()

    // Create a bufio.Writer
    writer := bufio.NewWriter(file)

    // Write data to the file
    data := []byte("Hello, world!\n")
    _, err = writer.Write(data)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    // Flush the buffer to ensure all data is written
    err = writer.Flush()
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    fmt.Println("Data written to file successfully.")
}
```

3. **Scanning lines from standard input using bufio.Scanner**:

```go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    // Create a bufio.Scanner for standard input
    scanner := bufio.NewScanner(os.Stdin)

    fmt.Println("Enter some text (press Ctrl+D to finish):")

    // Scan lines from standard input
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println("You entered:", line)
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("Error:", err)
    }
}
```

