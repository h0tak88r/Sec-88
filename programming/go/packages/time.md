# Time

#### Package Time in Go

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

    * `time.Ticker` is a struct that periodically sends the current time on its channel at a specified interval.
    * It's useful for tasks that need to be performed repeatedly at regular intervals.
    * You can stop the ticker by calling its `Stop()` method.

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

    * `time.NewTimer(duration)` creates a new timer that will send the current time on its channel after the specified duration.
    * Unlike `time.After()`, it allows you to stop the timer before it triggers.
    * It's useful when you need finer control over timer expiration.

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

* All these constructs (`time.After()`, `time.Ticker`, and `time.NewTimer()`) can be used effectively with Go's `select` statement.
* `select` allows you to wait on multiple channels simultaneously and perform different actions based on which channel sends a value first.

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

This code sets up both a ticker and a timer, and using `select`, it listens for events from both. It prints "Tick" every second and stops after the timer expires.
