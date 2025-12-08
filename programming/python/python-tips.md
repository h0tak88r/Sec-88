# Python Tips

A collection of handy Python tips and tricks to enhance your productivity and coding experience.

---

## Simple Python Server

Quickly serve files from the current directory using Python's built-in HTTP server:

```bash
python3 -m http.server -p 3000
```

Access the server at `http://localhost:3000` in your browser.

---

## Explore Methods and Attributes with `dir()`

The `dir()` function provides a list of available methods and attributes for any object. It's particularly useful for exploring built-in types like lists, dictionaries, and more.

```python
# Example: Using dir() on a list
my_list = [1, 2, 3, 4, 5]
print(dir(my_list))
```

### Pro Tip:
Combine `dir()` with `help()` for detailed documentation on specific methods or attributes.

```python
# Get detailed help on a method
help(my_list.append)
```

---

## Iterate with Indexes Using `enumerate()`

Use `enumerate()` to loop through a list while keeping track of the index:

```python
fruits = ['apple', 'banana', 'cherry']

for index, fruit in enumerate(fruits):
    print(f"{index}: {fruit}")
```

---

## Combine Iterables with `zip()`

The `zip()` function pairs elements from multiple iterables, making it easy to process them together:

```python
names = ['Alice', 'Bob', 'Charlie']
scores = [85, 92, 78]

for name, score in zip(names, scores):
    print(f"{name}: {score}")
```

---

## Clean Code with List Comprehensions

List comprehensions provide a concise way to create new lists:

```python
# Example: Create a list of squares
squares = [x**2 for x in range(10)]
print(squares)
```

---

## Debugging Made Easy with `pdb`

The `pdb` module is Python's built-in debugger. Use it to set breakpoints and step through your code.

```python
import pdb

# Set a breakpoint
pdb.set_trace()

# Example code
x = 10
y = 20
z = x + y
print(z)
```

---

## Simplify String Formatting with F-Strings

F-strings (introduced in Python 3.6) make string interpolation clean and intuitive:

```python
name = "John"
age = 30

print(f"My name is {name} and I am {age} years old.")
```

---

## Use Context Managers for Resource Management

Context managers (`with` statements) ensure proper handling of resources like files, even in case of errors:

```python
# Example: Reading a file
with open('example.txt', 'r') as file:
    data = file.read()
    print(data)
```

---

## Handle Multiple Exceptions

Simplify error handling by catching multiple exceptions in one `except` block:

```python
try:
    value = int("abc")
except (ValueError, TypeError) as e:
    print(f"Error occurred: {e}")
```