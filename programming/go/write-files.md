# Write Files

1. Writing a file using a struct and encoding data in JSON:

```go
import (
    "encoding/json"
    "os"
)

type Data struct {
    Field1 string
    Field2 int
    // Add more fields as needed
}

// Example of writing data to file using JSON encoding
func writeToJSONFile(filename string, data Data) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    if err := encoder.Encode(data); err != nil {
        return err
    }

    return nil
}
```

2. Writing byte slices using `os.Create` and `f.Write`:

```go
import "os"

func writeBytesToFile(filename string, data []byte) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    // write a slice of bytes to a file
    _, err = file.Write(data)
    if err != nil {
        return err
    }

    return nil
}
```

3. Writing strings using `f.WriteString()`:

```go
import "os"

func writeStringToFile(filename string, data string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    // write a string data to a file 
    _, err = file.WriteString(data)
    if err != nil {
        return err
    }

    return nil
}
```

4. Using `bufio` to write data to a file:

```go
import (
    "bufio"
    "os"
)

func writeWithBuffer(filename string, data string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := bufio.NewWriter(file)
    // Now WriteString() splt the string if it is bigger thatn the max buffer size
    _, err = writer.WriteString(data)
    if err != nil {
        return err
    }
    
    // flush writes any buffered data to the underlying io.writer
    err = writer.Flush()
    if err != nil {
        return err
    }

    return nil
}
```

5. Using `bufio` to write line by line:

```go
import (
    "bufio"
    "os"
)

func writeLinesToFile(filename string, lines []string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    for _, line := range lines {
        _, err := writer.WriteString(line + "\n")
        if err != nil {
            return err
        }
    }

    err = writer.Flush()
    if err != nil {
        return err
    }

    return nil
}
```

Example usage:

```go
data := Data{Field1: "Value1", Field2: 123} // Example data for JSON encoding

writeToJSONFile("data.json", data)
writeBytesToFile("data.bin", []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}) // Example byte slice
writeStringToFile("text.txt", "Hello, World!") // Example string
writeWithBuffer("buffered.txt", "Buffered write") // Example buffered write
writeLinesToFile("lines.txt", []string{"Line 1", "Line 2", "Line 3"}) // Example writing lines
```
