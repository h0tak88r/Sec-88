# Read Files

### 1. Read Entire File into Memory

You can read an entire file into memory using the `io/ioutil` package.

```go
package main

import (
    "io/ioutil"
    "log"
)

func main() {
    data, err := ioutil.ReadFile("example.txt")
    if err != nil {
        log.Fatal(err)
    }
    // Use 'data' as needed
}
```

### 2. Read File in Chunks

You can read a file in chunks by limiting the number of bytes to be read at a time. This approach is useful for large files to avoid loading everything into memory at once.

```go
package main

import (
    "os"
    "log"
)

func main() {
    file, err := os.Open("example.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    chunkSize := 1024 // Adjust chunk size as needed
    buffer := make([]byte, chunkSize)
    for {
        bytesRead, err := file.Read(buffer)
        if err != nil {
            if err.Error() == "EOF" {
                break // End of file reached
            }
            log.Fatal(err)
        }
        // Use 'buffer[:bytesRead]' as needed
    }
}
```

### 3. Read Line by Line

To read a file line by line, you can use the `bufio` package.

```go
package main

import (
    "bufio"
    "os"
    "log"
)

func main() {
    file, err := os.Open("example.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // Process 'line' as needed
    }
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
```
