# JavaScript (JS)

**1. Introduction to JS**

```javascript
var name = "hello";
var age = 19;
var field = "pentrest";
console.log(age);
console.log(name);
console.log(field);
alert(1);
confirm(1);
prompt(1);
```

**2. Comments**

```javascript
console.log("Hello from JavaScript"); //in-line comment
/* this is a multi-line comment */
```

**3. Data Types and Variables**

```javascript
/* Data Types: undefined, variables, null, bool, string, symbol, number, and object */
var name = "M8SZT8";
name = 8;
let ourname = "group";
const pi = 3.14;
```

**4. Storing Variables with the Assignment Operator**

```javascript
var a;
var b = 3;
console.log(a);
a = 7;
b = a;
console.log(a);
```

**5. Double Quote**

```javascript
// As in any language
var mystr = "I am a \"double quoted\" string inside \"quoted\"";
var mystr = 'I am a "double quoted" string inside "quoted"';
console.log(mystr);
```

**6. Escape Sequences**

```javascript
// Code output: /'   single quote/"   double quote//   backslash/n   new line /r   carriage return /t   tab/b   backspace/f   form feed
```

**7. Bracket Notation**

```javascript
var name = "M8SZT8";
var firstletterofname = "";
firstletterofname = name[0];
console.log(firstletterofname);
```

**8. String Immutability**

```javascript
var mystr = "jello world ";
// mystr[0] = "h"; // Error
mystr = "hello world ";
console.log(mystr);
```

**9. Find Nth Character**

```javascript
var name = "mszt";
var lastletterofname = name[name.length - 1];
console.log(lastletterofname);
var lastletterofname = name[name.length - 3];
console.log(lastletterofname);
```

**10. Word Blanks**

```javascript
function wordBlanks(myNoun, myAdjective, myVerb, myAdverb) {
    var result = "";
    result += "The " + myAdjective + " " + myNoun + " " + myVerb + " " + "to the store";
    return result;
}
console.log(wordBlanks("dog", "big", "ran", "quickly"));
```

**11. Arrays**

```javascript
// Example for Arrays
var ourArray = [["the universe", 42], ["everything", 101010]];
var myArray = [["Bulls", 23], ["White Sox", 45]];

// Example for Editing Arrays
var ourArray = [18, 64, 99];
ourArray[1] = 45;
var myArray = [18, 64, 99];
myArray[0] = 45;
console.log(myArray);

// Access Multi-Dimensional Arrays
var myArray = [[1,2,3], [4,5,6], [7,8,9], [[10,11,12], 13, 14]];
var myData = myArray[2][1];
console.log(myData);
```

**12. Push()**

```javascript
// Example Push array to other array
var ourArray = ["Stimpson", "J", "cat"];
ourArray.push(["happy", "joy"]);

// Setup
var myArray = [["John", 23], ["cat", 2]];
myArray.push(["dog", 3]);
```

**13. Pop()**

```javascript
// Example Remove last element in the array
var ourArray = [1,2,3];
var removedFromOurArray = ourArray.pop();

// Setup
var myArray = [["John", 23], ["cat", 2]];
var removedFromMyArray = myArray.pop();
console.log(myArray);
```

**14. Shift() & Unshift()**

```javascript
// Example remove first element from array
var ourArray = ["Stimpson", "J", ["cat"]];
var removedFromOurArray = ourArray.shift();

// Setup
var myArray = [["John", 23], ["dog", 3]];
var removedFromMyArray = myArray.shift();
// unshift add as the first element
removedFromMyArray.unshift("m8szt8");
```

**15. Functions**

```javascript
// Example
function ourReusableFunction() {
    console.log("Heyya, World");
}
ourReusableFunction();

// Only change code below this line
function reusableFunction() {


    console.log("Hi World");
}
reusableFunction();
```

**16. Return a Value from a Function**

```javascript
function timesFive(num) {
    return num * 5;
}
console.log(timesFive(5));
```

**17. If Statements**

```javascript
// Example
function trueOrFalse(wasThatTrue) {
    if (wasThatTrue) {
        return "Yes, that was true";
    }
    return "No, that was false";
}
console.log(trueOrFalse(true));
```

**18. Comparison with the Equality Operator**

```javascript
function testEqual(val) {
    if (val == 12) {
        return "Equal";
    }
    return "Not Equal";
}
console.log(testEqual(10));
```

**19. Strict Equality Operator**

```javascript
function testStrict(val) {
    if (val === 7) {
        return "Equal";
    }
    return "Not Equal";
}
console.log(testStrict(7));
```

**20. Inequality Operator**

```javascript
function testNotEqual(val) {
    if (val != 99) {
        return "Not Equal";
    }
    return "Equal";
}
console.log(testNotEqual(10));
```

Certainly! Let's continue with the JavaScript cheat sheet:

**21. Strict Inequality Operator**

```javascript
function testStrictNotEqual(val) {
    if (val !== "17") {
        return "Not Equal";
    }
    return "Equal";
}
console.log(testStrictNotEqual("17"));
```

**22. Greater Than Operator**

```javascript
function testGreaterThan(val) {
    if (val > 100) {
        return "Over 100";
    }
    if (val > 10) {
        return "Over 10";
    }
    return "10 or Under";
}
console.log(testGreaterThan(20));
```

**23. Greater Than or Equal To Operator**

```javascript
function testGreaterOrEqual(val) {
    if (val >= 20) {
        return "20 or Over";
    }
    if (val >= 10) {
        return "10 or Over";
    }
    return "Under 10";
}
console.log(testGreaterOrEqual(15));
```

**24. Less Than Operator**

```javascript
function testLessThan(val) {
    if (val < 25) {
        return "Under 25";
    }
    if (val < 55) {
        return "Under 55";
    }
    return "55 or Over";
}
console.log(testLessThan(45));
```

**25. Less Than or Equal To Operator**

```javascript
function testLessOrEqual(val) {
    if (val <= 12) {
        return "Smaller Than or Equal to 12";
    }
    if (val <= 24) {
        return "Smaller Than or Equal to 24";
    }
    return "Greater Than 24";
}
console.log(testLessOrEqual(20));
```

**26. Logical And Operator**

```javascript
function testLogicalAnd(val) {
    if (val >= 25 && val <= 50) {
        return "Yes";
    }
    return "No";
}
console.log(testLogicalAnd(30));
```

**27. Logical Or Operator**

```javascript
function testLogicalOr(val) {
    if (val < 10 || val > 20) {
        return "Outside";
    }
    return "Inside";
}
console.log(testLogicalOr(15));
```

**28. Else Statements**

```javascript
function testElse(val) {
    var result = "";
    if (val > 5) {
        result = "Bigger than 5";
    } else {
        result = "5 or Smaller";
    }
    return result;
}
console.log(testElse(4));
```

**29. Else If Statements**

```javascript
function testElseIf(val) {
    if (val > 10) {
        return "Greater than 10";
    } else if (val < 5) {
        return "Smaller than 5";
    } else {
        return "Between 5 and 10";
    }
}
console.log(testElseIf(7));
```

**30. Switch Statements**

```javascript
function caseInSwitch(val) {
    var answer = "";
    switch(val) {
        case 1:
            answer = "alpha";
            break;
        case 2:
            answer = "beta";
            break;
        case 3:
            answer = "gamma";
            break;
        case 4:
            answer = "delta";
            break;
    }
    return answer;
}
console.log(caseInSwitch(2));
```

Certainly! Let's continue with the JavaScript cheat sheet:

**31. Default Option in Switch Statements**

```javascript
function switchOfStuff(val) {
    var answer = "";
    switch(val) {
        case "a":
            answer = "Apple";
            break;
        case "b":
            answer = "Bird";
            break;
        case "c":
            answer = "Cat";
            break;
        default:
            answer = "Stuff";
            break;
    }
    return answer;
}
console.log(switchOfStuff("b"));
```

**32. Multiple Identical Options in Switch Statements**

```javascript
function sequentialSizes(val) {
    var answer = "";
    switch(val) {
        case 1:
        case 2:
        case 3:
            answer = "Low";
            break;
        case 4:
        case 5:
        case 6:
            answer = "Mid";
            break;
        case 7:
        case 8:
        case 9:
            answer = "High";
            break;
    }
    return answer;
}
console.log(sequentialSizes(5));
```

**33. Returning Boolean Values from Functions**

```javascript
function isLess(a, b) {
    return a < b;
}
console.log(isLess(10, 15));
```

**34. Return Early Pattern for Functions**

```javascript
function abTest(a, b) {
    if (a < 0 || b < 0) {
        return undefined;
    }
    return Math.round(Math.pow(Math.sqrt(a) + Math.sqrt(b), 2));
}
console.log(abTest(2, 2));
```

**35. Counting Cards**

```javascript
var count = 0;

function cc(card) {
    switch(card) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
            count++;
            break;
        case 10:
        case "J":
        case "Q":
        case "K":
        case "A":
            count--;
            break;
    }
    return count > 0 ? count + " Bet" : count + " Hold";
}
console.log(cc(2), cc(3), cc(7), cc('K'), cc('A'));
```

Certainly! Let's continue with the JavaScript cheat sheet:

**36. Build JavaScript Objects**

```javascript
var myDog = {
    "name": "Spot",
    "legs": 4,
    "tails": 1,
    "friends": ["everything!"]
};
```

**37. Accessing Object Properties with Dot Notation**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
var prop1Value = myObj.prop1; // Accessing property using dot notation
```

**38. Accessing Object Properties with Bracket Notation**

```javascript
var myObj = {
    "Space Name": "Kirk",
    "More Space": "Spock"
};
var propValue = myObj["Space Name"]; // Accessing property with spaces using bracket notation
```

**39. Accessing Object Properties with Variables**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
var prop = "prop1";
var propValue = myObj[prop]; // Accessing property using a variable
```

**40. Updating Object Properties**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
myObj.prop1 = "new value"; // Updating property value
```

**41. Add New Properties to a JavaScript Object**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
myObj.prop3 = "value3"; // Adding a new property
```

**42. Delete Properties from a JavaScript Object**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
delete myObj.prop1; // Deleting a property
```

**43. Using Objects for Lookups**

```javascript
function phoneticLookup(val) {
    var result = "";
    var lookup = {
        "alpha": "Adams",
        "bravo": "Boston",
        "charlie": "Chicago",
        "delta": "Denver",
        "echo": "Easy",
        "foxtrot": "Frank"
    };
    result = lookup[val];
    return result;
}
console.log(phoneticLookup("charlie"));
```

**44. Testing Objects for Properties**

```javascript
var myObj = {
    prop1: "value1",
    prop2: "value2"
};
function checkObj(checkProp) {
    return myObj.hasOwnProperty(checkProp) ? myObj[checkProp] : "Not Found";
}
console.log(checkObj("prop1"));
```

**45. Manipulating Complex Objects**

```javascript
var myMusic = [
    {
        "artist": "Billy Joel",
        "title": "Piano Man",
        "release_year": 1973,
        "formats": ["CD", "8T", "LP"],
        "gold": true
    },
    {
        "artist": "Michael Jackson",
        "title": "Thriller",
        "release_year": 1982,
        "formats": ["CD", "Cassette", "LP"],
        "gold": true
    }
];
```

**46. Accessing Nested Objects**

```javascript
var myStorage = {
    "car": {
        "inside": {
            "glove box": "maps",
            "passenger seat": "crumbs"
        },
        "outside": {
            "trunk": "jack"
        }
    }
};
var gloveBoxContents = myStorage.car.inside["glove box"];
```

**47. Accessing Nested Arrays**

```javascript
var myPlants = [
    {
        type: "flowers",
        list: ["rose", "tulip", "dandelion"]
    },
    {
        type: "trees",
        list: ["fir", "pine", "birch"]
    }
];
var secondTree = myPlants[1].list[1];
```

**48. Record Collection**

```javascript
var recordCollection = {
    2548: {
        albumTitle: "Slippery When Wet",
        artist: "Bon Jovi",
        tracks: ["Let It Rock", "You Give Love a Bad Name"]
    },
    2468: {
        albumTitle: "1999",
        artist: "Prince",
        tracks: ["1999", "Little Red Corvette"]
    },
    1245: {
        artist: "Robert Palmer",
        tracks: []
    }
};
function updateRecords(records, id, prop, value) {
    if (value === "") {
        delete records[id][prop];
    } else if (prop !== "tracks") {
        records[id][prop] = value;
    } else {
        if (records[id].hasOwnProperty("tracks")) {
            records[id].tracks.push(value);
        } else {
            records[id].tracks = [];
            records[id].tracks.push(value);
        }
    }
    return

 records;
}
```

**49. Iterate with JavaScript While Loops**

```javascript
var myArray = [];
var i = 0;
while (i < 5) {
    myArray.push(i);
    i++;
}
```

**50. Iterate with JavaScript For Loops**

```javascript
var myArray = [];
for (var i = 1; i <= 5; i++) {
    myArray.push(i);
}
```
