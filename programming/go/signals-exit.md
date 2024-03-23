# Signals-Exit

### Exit

* &#x20;to exit the app we can use `os.Exit(0)`
* [http://tldp.org/LDP/abs/html/exitcodes.html](http://tldp.org/LDP/abs/html/exitcodes.html)

```go
defer fmt.Println("bye")
// code zero indicates success, non-zero an error.
// defer will not run
os.Exit(9)
```

### Signals

* Notify causes package signal to relay incoming signals to "sigs".
* If no signals are provided, all incoming signals will be relayed to "sigs".
* Otherwise, just the provided signals will.

```go
{
	// channel that we will get signals on it
	sigs := make(chan os.Signal)
	// channel that we will use to shutdown the app
	done := make(chan bool)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		// blocking till we get os.Signal
		<-sigs
		// release resources
		// call shutdwon functions for HTTP server,  DB ...
		fmt.Println("\nDoing graceful shutdown")
		// send message to shutdown
		done <- true
	}()

	fmt.Println("waiting for os.Signal")
	// waiting internal shutdown message
	<-done
	fmt.Println("Exit")
}
```
