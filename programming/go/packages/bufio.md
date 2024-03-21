---
description: https://pkg.go.dev/bufio
---

# bufio

The bufio package in Go provides buffered I/O operations, allowing efficient reading and writing of data, especially when dealing with streams of data like files or network connections. Here's a simplified overview along with examples explaining its usage:

**1. Reading from a file using `bufio.Reader`:**

```go
import (
    "bufio"
    "os"
)

func readFromFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    // Create a bufio.Reader to efficiently read from the file
    reader := bufio.NewReader(file)

    for {
        // Read bytes until newline or EOF
        line, err := reader.ReadString('\n')
        if err != nil {
            break // EOF or error
        }
        // Process the line
        // Example: fmt.Println(line)
    }

    return nil
}
```

**2. Writing to a file using `bufio.Writer`:**

```go
import (
    "bufio"
    "os"
)

func writeToFile(filename string, data []byte) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    // Create a bufio.Writer to efficiently write to the file
    writer := bufio.NewWriter(file)

    // Write data to the file
    _, err = writer.Write(data)
    if err != nil {
        return err
    }

    // Ensure all buffered data is written to the file
    err = writer.Flush()
    if err != nil {
        return err
    }

    return nil
}
```

**3. Reading from standard input using `bufio.Scanner`:**

```go
import (
    "bufio"
    "fmt"
    "os"
)

func readFromStdin() {
    scanner := bufio.NewScanner(os.Stdin)

    // Scan through each line of input
    for scanner.Scan() {
        line := scanner.Text()
        // Process the input line
        // Example: fmt.Println(line)
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("Error reading standard input:", err)
    }
}
```

**4. Writing to standard output using `bufio.Writer`:**

```go
import (
    "bufio"
    "fmt"
    "os"
)

func writeToStdout(data string) {
    writer := bufio.NewWriter(os.Stdout)

    // Write data to standard output
    _, err := writer.WriteString(data)
    if err != nil {
        fmt.Println("Error writing to stdout:", err)
    }

    // Ensure all buffered data is written to stdout
    err = writer.Flush()
    if err != nil {
        fmt.Println("Error flushing buffer:", err)
    }
}
```
