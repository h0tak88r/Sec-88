# Json

### Encoding

```go
// Using Maps for aribitary json objects 
// or data you don't know it's tructure
mapD := map[string]int{"apple": 5, "lettuce": 7}
mapB, _ := json.Marshal(mapD)
fmt.Println(string(mapB))
----------------------------------------------

// Using Structs 
type response2 struct {
    Page   int      `json:"page"`
    Fruits []string `json:"fruits"`
}

res2D := &response2{
    Page:   1,
    Fruits: []string{"apple", "peach", "pear"}}
res2B, _ := json.Marshal(res2D)
fmt.Println(string(res2B))

--------------------------------------
// NewEncoder We can also stream JSON encodings directly to os.Writers like os.Stdout 
// or even HTTP response bodies.
d := map[string]int{"apple": 5, "lettuce": 7}
json.NewEncoder(os.Stdout).Encode(d)
```

### Decoding&#x20;

```go
// Using Maps for aribitary json objects or data you don't know it's tructure
byt := []byte(`{"num":6.13,"strs":["a","b"]}`)
var dat map[string]interface{}
if err := json.Unmarshal(byt, &dat); err != nil {
    panic(err)
}
fmt.Println(dat)
-----------------------------

// Using Structs
type response2 struct {
    Page   int      `json:"page"`
    Fruits []string `json:"fruits"`
}

str := `{"page": 1, "fruits": ["apple", "peach"]}`
res := response2{}
json.Unmarshal([]byte(str), &res)
fmt.Println(res)
fmt.Println(res.Fruits[0])
--------------------------------------

// Using NewDecoder()
response := `{"page": 1, "fruits": ["apple", "peach"]}`
resStruct := response2{}
json.NewEncoder(response.Body).Encode(resStruct)
```
