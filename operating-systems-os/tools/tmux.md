# tmux

> **Basic Commands**

* `tmux` -> start tmux
* `tmux ls` -> list sessions
* `CTRL+B then D` -> Detach Session
* `tmux attach -t [Session-Name]` -> Reattach Session
* `tmux new -s Session1` -> make new session
* **Ctrl+B D** —> Detach from the current session.
* **Ctrl+B %** —> Split the window into two panes horizontally.
* **Ctrl+B "** —> Split the window into two panes vertically.
* **Ctrl+B Arrow Key** --> (Left, Right, Up, Down) — Move between panes.
* **Ctrl+B X** —> Close pane.
* **Ctrl+B C** —> Create a new window.
* **Ctrl+B N** or **P** —> Move to the next or previous window.
* **Ctrl+B 0 (1,2...)** —> Move to a specific window by number.
* **Ctrl+B :** —> Enter the command line to type commands. Tab completion is available.
* **Ctrl+B ?** — View all keybindings. Press **Q** to exit.
* **Ctrl+B W** — Open a panel to navigate across windows in multiple sessions.

> **use the mouse**

* although the mouse is disabled by default. To enable it, first enter command mode by typing **Ctrl+B :**, then toggle the mouse on (or off) with the command `set -g mouse`.
