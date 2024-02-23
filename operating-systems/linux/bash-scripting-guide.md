# Bash Scripting guide

```bash
#!/bin/bash
# Variables
A="Ahmed" #add value to Variable
unset -v $A # Unset/remove value from Variable
-----------------------------------------------------
# Arguments
 Special Variable	 Variable Details
 $0	# The name of script itself
 $$	# Process id of current shell
 $*	# Values of all the arguments. All agruments are double quoted
 $#	# Total number of arguments passed to script
 $@	# Values of all the arguments
 $?	# Exit status id of last command
 $!	# Process id of last command
------------------------------------------------------------------------------------
#Command Substituting using bracktick, '(),$'
date
V=$(date)
G=`date`
echo $V
echo $G
----------------------------------------------------------------------------------------------
# If 
if [<Condition>]
then
	<commands>
else
	<commands>
elif [<condition>]
then 
	<commands>
else
fi
------------------------------------------------------------------------------------------------
# for loop
for $variablename in <list>
do 
	<action>
done
# Online
for i in {1..10} ;do echo "Number is $i" ;done
---------------------------------------------------------------------------------------------
# while 
while [<condition>]
do
	<perform an action>
done
---------------------------------------------------------------------------------------------
# Boolean Logical Operators
!   # Not
||  # Or
&&  # AND
---------------------------------------------------------------------------------------------
# Functions
function_name(){
commands
}

#Onliner
functione_name(){commands;}

function_name   #call function

# Example 
hello_world () {
   echo 'hello, world'
}

hello_world

--------------------------------------------------------------------------------------
# Scope !
var1='A'
var2='B'

my_function () {
  local var1='C'
  var2='D'
  echo "Inside function: var1: $var1, var2: $var2"
}

echo "Before executing function: var1: $var1, var2: $var2"
'''
output:
Before executing function: var1: A, var2: B
Inside function: var1: C, var2: D
After executing function: var1: A, var2: D
'''
-----------------------------------------------------------------------------------
# String comparisons
if [ "$(whoami)" != 'root' ]; then
        echo "You have no permission to run $0 as non-root user."
        exit 1;
fi
# or 

test "$(whoami)" != 'root' && (echo you are using a non-privileged account; exit 1)
---------------------------------------------------------------------------------------
```
