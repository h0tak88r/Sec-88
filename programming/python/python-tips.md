# Python Tips

* Simple Python server

```python
python3 -m http.server -p 3000
```

* use dir() to know what available methods and attributes for lists and dictionaries,...etc

> In Python, the `dir()` function is used to get a list of names in the current local scope or the attributes of an object. When you use `dir()` on a built-in object like a list or dictionary, it will show you the available methods and attributes for that objec

```python
# Create a list
my_list = [1, 2, 3, 4, 5]

# Use dir() to see available methods and attributes for the list
print(dir(my_list))
```
