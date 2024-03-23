# Time

**Overview:**

* The `time` package in Go provides functionality for working with time-related operations, such as getting the current time, sleeping, timers, and tickers.
* It offers structs like `Time`, `Duration`, and functions like `Now()`, `Sleep()`, `After()`, `Ticker()`, and `NewTimer()` for various time-related tasks.

**Usage of `time.After()`, `time.Ticker`, and `time.NewTimer()`:**

1.  **`time.After()`**:

    * `time.After(duration)` returns a channel that receives the current time after the specified duration.
    * It's commonly used to create a timeout mechanism or to schedule an action to occur after a specific duration.
    * It's a non-blocking operation.

    Example:

    ```go
    select {
    case <-time.After(1 * time.Second):
        fmt.Println("Timeout!")
    }
    ```
2.  **`time.Ticker`**:

    Example:

    ```go
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            fmt.Println("Tick")
        }
    }
    ```
3.  **`time.NewTimer()`**:

    Example:

    ```go
    timer := time.NewTimer(2 * time.Second)
    defer timer.Stop()

    select {
    case <-timer.C:
        fmt.Println("Timer expired")
    }
    ```

**Using with `select`:**

Example:

```go
ticker := time.NewTicker(1 * time.Second)
defer ticker.Stop()

timer := time.NewTimer(5 * time.Second)
defer timer.Stop()

for {
    select {
    case <-ticker.C:
        fmt.Println("Tick")
    case <-timer.C:
        fmt.Println("Timer expired")
        return
    }
}
```
