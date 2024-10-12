# Smali Code Patching Guide

### Changing the Return Value in Methods

#### Example: `checkDebugger()` Function

The original `checkDebugger()` function in smali checks whether a debugger is connected. By modifying this function, we can change its behavior to always return a specific result.

#### Original Code

```smali
.method public checkDebugger()Z
    .locals 1

    .line 30
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z

    move-result v0

    return v0
.end method
```

In this case, the method returns the actual result of `isDebuggerConnected()`. To modify it, we can overwrite the value of `v0` before returning it.

#### Modified Code

```smali
.method public checkDebugger()Z
    .locals 1

    .line 30
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z

    move-result v0

    const v0, 0x0  # Overwrite the result to always be false

    return v0
.end method
```

Now, the method always returns `false` (represented by `0x0`), no matter the actual result of the `isDebuggerConnected()` function.

***

### Flipping the Logic in Conditionals (IF-ELSE-GOTO Patching)

#### Example: Processing `getHit()` Method in a Game

Here, we modify a method that processes a player getting hit, depending on whether the player has a shield. By flipping the conditional logic, we can change how the game behaves.

#### Original Code

```smali
.method public getHit()V
    .locals 3

    .line 37
    iget-boolean v0, p0, Lcom/apphacking/smalitwo/Player;->shield:Z

    const/4 v1, 0x0
    const/4 v2, 0x1

    if-ne v0, v2, :cond_0  # If shield is not active, go to cond_0

    .line 39
    iput-boolean v1, p0, Lcom/apphacking/smalitwo/Player;->shield:Z
    goto :goto_0

    .line 42
    :cond_0
    iget v0, p0, Lcom/apphacking/smalitwo/Player;->lives:I
    sub-int/2addr v0, v2
    iput v0, p0, Lcom/apphacking/smalitwo/Player;->lives:I

    .line 44
    if-lez v0, :cond_1

    .line 46
    iput-boolean v2, p0, Lcom/apphacking/smalitwo/Player;->state:Z
    goto :goto_0

    .line 49
    :cond_1
    iput-boolean v1, p0, Lcom/apphacking/smalitwo/Player;->state:Z

    .line 52
    :goto_0
    return-void
.end method
```

In this code, when the player has a shield (`if-ne v0, v2`), they don't lose lives. To flip this logic, we can change the `if-ne` to `if-eq` so that now the player will lose lives when they have a shield.

#### Modified Code

```smali
.method public getHit()V
    .locals 3

    .line 37
    iget-boolean v0, p0, Lcom/apphacking/smalitwo/Player;->shield:Z

    const/4 v1, 0x0
    const/4 v2, 0x1

    if-eq v0, v2, :cond_0  # If shield is active, go to cond_0 (Flipped Logic)

    .line 39
    iput-boolean v1, p0, Lcom/apphacking/smalitwo/Player;->shield:Z
    goto :goto_0

    .line 42
    :cond_0
    iget v0, p0, Lcom/apphacking/smalitwo/Player;->lives:I
    sub-int/2addr v0, v2
    iput v0, p0, Lcom/apphacking/smalitwo/Player;->lives:I

    .line 44
    if-lez v0, :cond_1

    .line 46
    iput-boolean v2, p0, Lcom/apphacking/smalitwo/Player;->state:Z
    goto :goto_0

    .line 49
    :cond_1
    iput-boolean v1, p0, Lcom/apphacking/smalitwo/Player;->state:Z

    .line 52
    :goto_0
    return-void
.end method
```

Now, the game logic is reversed, and the player loses lives when they have a shield.

***

### Deleting Code to Alter Game Logic

In some cases, you can remove certain instructions to alter the game behavior entirely.

#### Example: `processGame()` Method in Java

```java
public void processGame() {
    // Create new Player Object
    Player player = new Player();
    if (player.hasItem(MasterCap)) {
        player.power += 100;
    } else {
        player.power += 10;
    }
}
```

In smali, this code translates into conditional logic that adds power based on whether the player has the `MasterCap`.

#### Original Smali Code

```smali
.method public hasItem(Lcom/apphacking/smalitwo/Player;)V
    .locals 1
    .param p1, "player"    # Lcom/apphacking/smalitwo/Player;

    .line 15
    iget-boolean v0, p1, Lcom/apphacking/smalitwo/Player;->masterCap:Z

    if-eqz v0, :cond_0  # Check if the player does not have the MasterCap

    .line 17
    iget v0, p1, Lcom/apphacking/smalitwo/Player;->power:I
    add-int/lit8 v0, v0, 0x64  # Add 100 power
    iput v0, p1, Lcom/apphacking/smalitwo/Player;->power:I

    goto :goto_0

    .line 20
    :cond_0
    iget v0, p1, Lcom/apphacking/smalitwo/Player;->power:I
    add-int/lit8 v0, v0, 0xA   # Add 10 power
    iput v0, p1, Lcom/apphacking/smalitwo/Player;->power:I

    .line 23
    :goto_0
    return-void
.end method
```

By removing the `if-eqz` line, the game will always give the player 100 power, regardless of whether they have the `MasterCap`.

#### Modified Code

```smali
.method public hasItem(Lcom/apphacking/smalitwo/Player;)V
    .locals 1
    .param p1, "player"    # Lcom/apphacking/smalitwo/Player;

    .line 17
    iget v0, p1, Lcom/apphacking/smalitwo/Player;->power:I
    add-int/lit8 v0, v0, 0x64  # Always add 100 power
    iput v0, p1, Lcom/apphacking/smalitwo/Player;->power:I

    .line 23
    return-void
.end method
```

By eliminating the condition, the player now gets a 100 power boost unconditionally.

***

### Changing Jump Instructions

Jump instructions (`goto`, `if-*`) can be modified to change how the program flow behaves.

#### Example: Modifying GOTO

In the same method, we can alter the jump instruction to make the player gain 110 power instead of choosing between 100 or 10.

#### Original Code

```smali
goto :goto_0
```

#### Modified Code

```smali
goto :cond_0  # Redirect to give both 10 and 100 power
```

Now the program first adds 10 power and then immediately adds 100 power, giving a total of 110.

***

### Additional Method: Manipulating Currency in a Game

#### New Method: `increaseCurrency()`

This method will increase the player's in-game currency.

```smali
.method public increaseCurrency()V
    .locals 2

    .line 25
    iget v0, p0, Lcom/apphacking/smalitwo/Player;->currency:I
    const/16 v1, 0x3E8  # Add 1000 currency
    add-int/2addr v0, v1
    iput v0, p0, Lcom/apphacking/smalitwo/Player;->currency:I

    .line 

28
    return-void
.end method
```

Now the player will receive 1000 in-game currency every time this method is called.

