# Git

```bash
# Git Commands

# Setting up git
http://git-scm.com/download/mac  #to download and install Git
git config --global user.name "User Name"
git config --global user.email "email"


# Basic Commands
git init                        # Initializing a repository in an existing directory
git add .                       # Adding all files changes in a directory
git add filename                # Add Specific file
git add -A                      # Adding all files
git add -p                      # Choosing what changes to add 
git commit -am "update"         # Commit staged files
git commit filename -m 'commit message'    # Add file and commit
git commit -am 'insert commit message'     # Add file and commit staged file
git push -u origin branchname              # Pushing local branch to remote
git push origin master --force             # Force Pushing
git status                      # git status or branch
git checkout -b branchname      # Creating a local branch
git checkout -                  # Switching between 2 branches
git branch -d branchname        # Deleting a local branch  (this won't let you dete a branch that hasn't been merged yet)
git branch -rd origin/branchname # Deleting a remote branch
git push origin --delete branchname
git branch -D branchname        # this WILL delete a branch even if it hasn't been merged yet!
git remote prune origin         # Remove any remote refs you have locally that have been removed from your remote 
git branch -a                   # Viewing all branches, including local and remote branches
git branch -a --merged          # Viewing all branches that have been merged into your current branch, including local and remote
git branch -a --no-merged       # Viewing all branches that haven't been merged
git branch                      # Viewing local branches
git branch -r                   # Viewing remote branches
git push origin +branchname     # Pushing local branch after rebasing master into local branch- git fetch origin                # This will fetch all the remote branches for you.
git pull origin master          # Updating a local repository with changes from a Github repository
git branch --set-upstream-to=origin/foo foo # Tracking existing branch


#### Merging branch to trunk/master
git checkout trunk/master       # First checkout trunk/master
git merge branchname            # Now merge branch to trunk/master
git merge --abort               # To cancel a merge

#### Resetting
git reset --mixed [sha]                   # Mixes your head with a give sha - This lets you do things like split a commit
git reset HEAD origin/master -- filename  # Upstream master
git reset HEAD -- filename                # The version from the most recent commit
git reset HEAD^ -- filename               # git reset HEAD^ -- filename
git reset --hard sha                      # Move head to specific commit
Reset the staging area and the working directory to match the most recent commit. In addition to unstaging changes, the --hard flag tells Git to overwrite all changes in the working directory, too.
git reset --hard

#### Git remote
git remote show origin                                      # Show where 'origin' is pointing to and also tracked branches
git remote -v                                               # Show where 'origin' is pointing to
git remote set-url origin https://github.com/user/repo.git  # Change the 'origin' remote's URL
git remote add [NAME] https://github.com/user/fork-repo.git # Add a new 'origin' (Usually use to 'rebase' from forks)

#### Git grep
git grep 'something'                      # 'Searches' for parts of strings in a directory
git grep -n 'something'                   # 'Searches' for parts of strings in a directory and the -n prints out the line numbers where git has found matches
git grep -C<number of lines> 'something'  # 'Searches' for parts of string in a context (some lines before and some after the grepped term)
git grep -B<number of lines> 'something'  # 'Searches' for parts of string and also shows lines BEFORE the grepped term
git grep -A<number of lines> 'something'  # 'Searches' for parts of string and also shows lines AFTER the grepped term

#### Git log
git log                                   # Show a list of all commits in a repository. This command shows everything about a commit, such as commit ID, author, date and commit message.
git log -p                                # List of commits showing commit messages and changes
git log -S 'something'                    # List of commits with the particular expression you are looking for
git log --author 'Author Name'            # List of commits by author
git log --oneline                         # Show a list of commits in a repository in a more summarised way. This shows a shorter version of the commit ID and the commit message.
git log --since=yesterday                 # Show a list of commits in a repository since yesterday
git log --grep "term" --author "name"     # Shows log by author and searching for specific term inside the commit message

#### Checking what you are committing
git diff                                  # See all (non-staged) changes done to a local repo
git diff --cached                         # See all (staged) changes done to a local repo
git diff --stat origin/master             # Check what the changes between the files you've committed and the live repo

#### Useful commands
git tag --contains [sha]                  # Check if a sha is in production
git shortlog -s --author 'Author Name'    # Number of commits by author
git shortlog -s -n                        # List of authors and commits to a repository sorted alphabetically
git shortlog -n --author 'Author Name'    # List of commit comments by author (This also shows the total number of commits by the author)
git shortlog -s -n                        # Number of commits by contributors
git checkout -- filename                  # Undo local changes to a File
git cat-file sha -p                       # Shows more detailed info about a commit

# Show number of lines added and removed from a repository by an author since some time in the past.
git log --author="Author name" --pretty=tformat: --numstat --since=month | awk '{ add += $1; subs += $2; loc += $1 - $2 } END { printf "added lines: %s, removed lines: %s, total lines: %s\n", add, subs, loc }'

# Shows the log in a more consisted way with the graph for branching and merging
lg = log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit


### Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push -u origin my-new-feature`
5. Submit a pull request - cheers!

### Handle Proxy
git config --global  http.proxy http://proxy_address:proxy_port    # Set   http  proxy
git config --global  https.proxy http://proxy_address:proxy_port   # set   https proxy
git config --global --unset http.proxy                             # unset http  proxy
git config --global --unset https.proxy                            # unset https proxy

# JEKYLL Deployment
git remote add origin <repository_url>
bundle exec jekyll s                                # starts a local development server that serves your Jekyll site  
JEKYLL_ENV=production bundle exec jekyll b          # This command builds your Jekyll site for production.     
git add .
git commit -m "Initial commit"
git push -u origin master
```
