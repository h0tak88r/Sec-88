# SetMethods

```python
# -----------------
# -- Set Methods --
# -----------------

# clear() - Removes all elements from the set
a = {1, 2, 3}
a.clear()
print(a)  # set()

print("=" * 50)

# union() - Combines two or more sets, eliminating duplicates
b = {"One", "Two", "Three"}
c = {"1", "2", "3"}
x = {"Zero", "Cool"}
print(b | c)  # {'Three', '1', '2', 'Two', '3', 'One'}
print(b.union(c, x))  # {'Three', 'Zero', 'Cool', '1', '2', 'Two', '3', 'One'}

print("=" * 50)

# add() - Adds an element to the set
d = {1, 2, 3, 4}
d.add(5)
d.add(6)
print(d)  # {1, 2, 3, 4, 5, 6}

print("=" * 50)

# copy() - Creates a shallow copy of the set
e = {1, 2, 3, 4}
f = e.copy()
print(e)  # {1, 2, 3, 4}
print(f)  # {1, 2, 3, 4}
e.add(6)
print(e)  # {1, 2, 3, 4, 6}
print(f)  # {1, 2, 3, 4} (shallow copy)

print("=" * 50)

# remove() - Removes a specified element from the set; raises an error if the element is not present
g = {1, 2, 3, 4}
g.remove(1)
# g.remove(7)  # Raises an error
print(g)  # {2, 3, 4}

print("=" * 50)

# discard() - Removes a specified element from the set without raising an error if the element is not present
h = {1, 2, 3, 4}
h.discard(1)
h.discard(7)  # No error for non-existent element
print(h)  # {2, 3, 4}

print("=" * 50)

# pop() - Removes and returns a random element from the set
i = {"A", True, 1, 2, 3, 4, 5}
print(i.pop())  # A

print("=" * 50)

# update() - Adds elements from another set (or iterable) to the set
j = {1, 2, 3}
k = {1, "A", "B", 2}
j.update(['Html', "Css"])
j.update(k)
print(j)  # {'A', 1, 2, 3, 'B', 'Html', 'Css'}

print("=" * 50)

# difference() - Returns the difference of two sets (elements present in the first set but not in the second)
a = {1, 2, 3, 4}
b = {1, 2, 3, "Osama", "Ahmed"}
print(a.difference(b))  # {4}

print("=" * 50)

# difference_update() - Removes elements of another set from the set (in-place)
c = {1, 2, 3, 4}
d = {1, 2, "Osama", "Ahmed"}
c.difference_update(d)
print(c)  # {3, 4}

print("=" * 50)

# intersection() - Returns the common elements of two sets
e = {1, 2, 3, 4, "X", "Osama"}
f = {"Osama", "X", 2}
print(e.intersection(f))  # {'X', 2, 'Osama'}

print("=" * 50)

# intersection_update() - Updates the set with the common elements of itself and another set (in-place)
g = {1, 2, 3, 4, "X", "Osama"}
h = {"Osama", "X", 2}
g.intersection_update(h)
print(g)  # {'X', 2, 'Osama'}

print("=" * 50)

# symmetric_difference() - Returns the symmetric difference of two sets (elements present in either set, but not in both)
i = {1, 2, 3, 4, 5, "X"}
j = {"Osama", "Zero", 1, 2, 4, "X"}
print(i.symmetric_difference(j))  # {3, 5, 'Zero', 'Osama'}

print("=" * 50)

# symmetric_difference_update() - Updates the set with the symmetric difference of itself and another set (in-place)
k = {1, 2, 3, 4, 5, "X"}
l = {"Osama", "Zero", 1, 2, 4, "X"}
k.symmetric_difference_update(l)
print(k)  # {3, 5, 'Zero', 'Osama'}

print("=" * 50)

# issuperset() - Checks if one set is a superset of another (contains all elements and possibly more)
a = {1, 2, 3, 4}
b = {1, 2, 3}
c = {1, 2, 3, 4, 5}
print(a.issuperset(b))  # True
print(a.issuperset(c))  # False

print("=" * 50)

# issubset() - Checks if one set is a subset of another (contains all elements and possibly fewer)
d = {1, 2, 3, 4}
e = {1, 2, 3}
f = {1, 2, 3, 4, 5}
print(d.issubset(e))  # False
print(d.issubset(f))  # True

print("=" * 50)

# isdisjoint() - Checks if two sets have no common elements
g = {1, 2, 3, 4}
h = {1, 2, 3}
i = {10, 11, 12}
print(g.isdisjoint(h))  # False
print(g.isdisjoint(i))  # True
```
