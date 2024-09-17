# Bash Scripting guide

```bash
#!/bin/bash

# ----------------------------------------------
# Variables
A="Ahmed"            # Assign value to a variable
unset -v A           # Unset/remove value from the variable (note: no $ when unsetting)

# You can also use `declare` to specify variable attributes
declare -i num=10    # Declares an integer variable
declare -r PI=3.14   # Declares a read-only variable
echo "The value of A is: $A"
echo "The value of num is: $num"

# ----------------------------------------------
# Arguments (Positional Parameters)
# Special Variables:
# $0   : The name of the script itself
# $$   : Process ID of the current shell
# $*   : All arguments passed (treated as a single word)
# $#   : Total number of arguments passed
# $@   : All arguments passed (treated individually)
# $?   : Exit status of the last command
# $!   : Process ID of the last background command

echo "Script name: $0"
echo "PID of the shell: $$"
echo "All arguments (as a single string): $*"
echo "All arguments (individually): $@"
echo "Total number of arguments: $#"

# ----------------------------------------------
# Command Substitution using backticks `` or $()
date
V=$(date)         # Using $()
G=`date`          # Using backticks
echo "Using \$(): $V"
echo "Using backticks: $G"

# Command substitution can be used with other commands:
echo "Current directory: $(pwd)"
file_count=$(ls | wc -l)
echo "There are $file_count files in the current directory."

# ----------------------------------------------
# Conditional Statements (if, elif, else)
if [ <Condition> ]
then
    <commands>
elif [ <another condition> ]
then
    <commands>
else
    <commands>
fi

# Example:
if [ $(whoami) == 'root' ]; then
    echo "You are the root user."
else
    echo "You are not the root user."
fi

# Single-line if statement
[ -f /etc/passwd ] && echo "/etc/passwd exists"

# ----------------------------------------------
# Loops: for loop
for varname in <list>
do
    <commands>
done

# Example: Iterating through a list of numbers
for i in {1..10}; do
    echo "Number is $i"
done

# Example: Iterating over a list of files
for file in *.txt; do
    echo "Processing $file..."
done

# ----------------------------------------------
# Loops: while loop
while [ <condition> ]
do
    <commands>
done

# Example:
counter=1
while [ $counter -le 5 ]; do
    echo "Counter: $counter"
    ((counter++))
done

# ----------------------------------------------
# Boolean Logical Operators
!   # NOT
||  # OR
&&  # AND

# Example:
test -f /etc/passwd && echo "File exists" || echo "File does not exist"

# ----------------------------------------------
# Functions
function function_name {
    <commands>
}

# Inline (one-liner function)
function_name(){ <commands>; }

# Calling a function:
function_name

# Example:
hello_world () {
    echo "Hello, World!"
}

hello_world  # Call the function

# Function with arguments:
greet () {
    echo "Hello, $1!"
}

greet "Ahmed"  # Pass "Ahmed" as an argument

# ----------------------------------------------
# Variable Scope
var1="A"
var2="B"

my_function() {
    local var1="C"  # local: limited to the function
    var2="D"        # global: affects outside the function
    echo "Inside function: var1: $var1, var2: $var2"
}

echo "Before function: var1: $var1, var2: $var2"
my_function
echo "After function: var1: $var1, var2: $var2"

# Output:
# Before function: var1: A, var2: B
# Inside function: var1: C, var2: D
# After function: var1: A, var2: D

# ----------------------------------------------
# String Comparisons
if [ "$(whoami)" != "root" ]; then
    echo "You must run this script as root!"
    exit 1
fi

# Another way:
test "$(whoami)" != "root" && (echo "Not a root user"; exit 1)

# String comparison operators:
# -z: string is empty
# -n: string is not empty
str="Hello"
if [ -n "$str" ]; then
    echo "String is not empty."
fi

# ----------------------------------------------
# File Testing
# Test if a file exists (-f), is a directory (-d), or has execute permission (-x)
if [ -f "/etc/passwd" ]; then
    echo "/etc/passwd exists."
fi

# Combining conditions with logical operators:
if [ -f "/etc/passwd" ] && [ -x "/etc/passwd" ]; then
    echo "/etc/passwd exists and is executable."
fi

# ----------------------------------------------
# Arrays
array=("apple" "banana" "cherry")
echo "First item: ${array[0]}"
echo "All items: ${array[@]}"
echo "Total items: ${#array[@]}"

# Looping through an array
for item in "${array[@]}"; do
    echo "$item"
done

# ----------------------------------------------
# Input and Output Redirection
echo "This is a test" > output.txt   # Redirect output to a file
cat < output.txt                     # Read input from a file
```
