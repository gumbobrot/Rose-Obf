print("hello, world!\nHI")

print("wassup?!?!?!\nHI")

# Dictionaries are a key-value object in Python.
# Like sets, you create them using { and }, but unlike sets, they must be
# created as key-value pairs using the : symbol.
# The values used can be any object.
my_dictionary = {"banana": "$10.00", "cheese": True}

# Access items like with lists, except keys are usually strings.
my_dictionary["banana"]  # returns the string '$10.00'
my_dictionary["cheese"]  # returns True

# If accessing a key that doesn't exist using [ ], Python raises a KeyError.
# e.g. my_dictionary['optimus'] will raise a KeyError.

# Adding new items.
my_dictionary["optimus"] = "Truck"

# Changing existing items.
my_dictionary["cheese"] = False

# Get all the keys. (used for looping/iterating later on)
my_dictionary.keys()

# Get all the values.
my_dictionary.values()

# Get all the items (key-value pairs)
my_dictionary.items()

# See help(dict) for other methods.

for i in range(1, 10):
    print(i)

# A tuple is a read-only data structure for storing collections that
# don't need to be changed. You create one using ( and ) characters.

# Create a tuple with ( and )
my_tuple = (1, 2, "hello", 3.14, False, "hello")

print(type(my_tuple))

# Access an item by index using [ and ]. Indexes start at 0
print(my_tuple[0])

print(my_tuple[3])

# Access a container from right-to-left
print(my_tuple[-1])
print(my_tuple[-3])

# Count number of items in a tuple
my_tuple.count("hello")
my_tuple.count(3.14)
my_tuple.count("blahblah")

# Search and get the index of an item
my_tuple.index("hello")

my_tuple.index(3.14)
my_tuple.index(False)


# Trying to change the value of an item in a tuple causes an error.


# Warning: If creating a tuple with only 1 item, you need to use this special syntax with a comma.
my_tuple2 = (42,)
type(my_tuple2)  # is a 'tuple' type

# If you forget the comma, then Python doesn't create the tuple.
fake_tuple = 42
type(fake_tuple)  # is an 'int' type

import random
import math
from functools import reduce


# Define a custom function to calculate factorial recursively
def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n - 1)


# Generate a random list of numbers using list comprehension
random_numbers = [random.randint(1, 100) for _ in range(20)]

# Filter even numbers from the list
even_numbers = list(filter(lambda x: x % 2 == 0, random_numbers))

# Find square roots of all numbers in the list
square_roots = list(map(math.sqrt, random_numbers))

# Calculate the sum of all numbers in the list
total_sum = reduce(lambda x, y: x + y, random_numbers)

# Print the list of random numbers
print("Random numbers:", random_numbers)

# Print the list of even numbers
print("Even numbers:", even_numbers)

# Print the list of square roots
print("Square roots:", square_roots)

# Print the total sum of the numbers
print("Total sum:", total_sum)

# Generate a random dictionary with random keys and values
random_dict = {chr(random.randint(97, 122)): random.randint(1, 100) for _ in range(10)}

# Print the random dictionary
print("Random dictionary:", random_dict)

# Calculate the factorial of a random number
random_number = random.choice(random_numbers)
factorial_result = factorial(random_number)

# Print the factorial result
print("Factorial of {}: {}".format(random_number, factorial_result))
