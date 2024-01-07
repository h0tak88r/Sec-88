# Set



```python
# -----------------------------
# -- Set --
# ---------
# [1] Set Items Are Enclosed in Curly Braces
# [2] Set Items Are Not Ordered And Not Indexed
# [3] Set Indexing and Slicing Cant Be Done
# [4] Set Has Only Immutable Data Types (Numbers, Strings, Tuples) List and Dict Are Not
# [5] Set Items Is Unique
# -----------------------------

# Not Ordered And Not Indexed
mySetOne = {"sallam", "h0tak88r", 88}
print(mySetOne)
print(mySetOne[0]) # Error

# Slicing Cant Be Done
mySetTwo = {1, 2, 3, 4, 5, 6}
print(mySetTwo[0:3]) # Error



# Has Only Immutable Data Types
# mySetThree = {"Osama", 100, 100.5, True, [1, 2, 3]} # unhashable type: 'list'
mySetThree = {"sallam", 88, 88.8, True, (8, 88, 888)}
print(mySetThree)
# {'sallam', True, (8, 88, 888), 88, 88.8}

#----------------------------------------------
# Items Is Unique
mySetFour = {8, 88, "sallam", "One", "h0tak88r", 888}
print(mySetFour)
# {'sallam', 888, 8, 88, 'h0tak88r', 'One'}

```
