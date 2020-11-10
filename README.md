# How to Git

## Basic git commands
```git
$ git clone <path>
$ git add <file>
$ git status
$ git commit -m <file>
$ git push
```

## Other basic git commands
```git
$ git init
```
Creates an empty git repo.

```git
$ git diff <file>
```
Prints out the difference between last `git add` of the file and the current content of the file.

```git
$ git log
```
Prints out the git log.
To print out the crucial info only, use `git log --pretty=oneline`
Some other useful params including `--graph`,`--abbrev-commit`, etc.


## Git time machine
In Git, we use `HEAD` to represent the current version.
To get the last version of the `HEAD`, use `HEAD^`, similarly, to get the second last version, use `HEAD^^`.
To get the n^th^ last version of `HEAD`, use `HEAD~100`.
```git
$ git reset --hard HEAD^
```
Reset the current version to its previous version.
After executing `git reset`, `git log` command will not print out the log for the original `HEAD` version. 
To recover the original `HEAD` version, we must remember the _commit id_ of that version.
```git
$ git reflog
```
This piece of command can print out all git commands that we have run. 
We can now get the _commit id_ of the version which we want to recover. Now we can run `git reset --hard <commit_id>` and happy days!

## Remedies in Git
```git
$ git checkout -- <file>
```
_Remove_ any changes we have made to the file since its last `git add`.
This command can also be used to recover a deleted file.
(This command simply replaces the file with the version of file recorded in Git).
```git
$ git reset HEAD <file>
```
_Unstage_ any changes we have made. Then we can run `git checkout -- <file>` to actually remove stuff. (How to fix a wrong `git add`).

## Branches in Git
#### Tao begets One...
```git
$ git checkout -b foobar
```
This command creates a branch called 'foobar' and switch to this branch. It is the same as the following commands:
```git
$ git branch foobar
$ git checkout foobar
```
If you find `git checkout` is a bit confusing, you may also use 
```git
$ git switch foobar
```
to switch to another branch.
###### ALERT: Lab computers does not seem to support `git switch`! Use git checkout instead!
```git
$ git branch
```
This simple command tells you the names of all branches and print an extra '*' to the front of the current branch.
#### Guess I sorted the merge!
To merge two branches, you first need to switch to the target branch.
```git
$ git switch target
```
Then we run...
```git
$ git merge source
```
to merge the changes made on `source` branch to `target` branch.
If you feel that there is no need to keep the `source` branch at this point, run
```git
$ git branch -d source
```
to delete the `source` branch.
#### Conflicts
##### Fast-forward
When merging two branches, if both branches has the same commit X in their history, and the source branch has several commits after X while the target branch has no commits after X, we say that the source branch is _ahead of_ the target branch.
```
4Gtf7 --- 19DH1            <= target
            |
          2xcp2 --- C01df  <= source
```
When Git performs the merging, it will recognize this situation and simply perform a _fast-forward_ merge, that is, it fast forwards the master's branch's pointer to match the merged commits.
To manually disable _fast-forwarding_ and force Git to create a new commit when merging, run
`git merge --no-ff -m "merge with no-ff" source`
##### Non-fast-forward
However, in this scenario
```
4Gtf7 --- 19DH1 --- kgK01  <= target
            |
          2xcp2 --- C01df  <= source
```
When we try to merge `source` to `target`, we get a CONFLICT message from Git. This means we need to solve the conflicts before we can actually merge.
We can run `git status` at this point to know which file(s) has conflict.
Git will mark out the conflicting content in a file with `<<<<<<<`, `=======` and `>>>>>>>`. e.g.
```
This part has not been modified.
<<<<<<< yours:foobar.txt
Changes made in this branch.
=======
Changes made in the other branch.
>>>>>>> theirs:foobar.txt
This part has not been modified as well.
```
Contents from `<<<<<<<` to `=======` is the current change (changes in current branch), contents from `=======` to `>>>>>>>` is the incoming change (changes in the other branch).
You may now resolve all conflicts in the `target` branch and then run 
```git
$ git add foobar.txt
$ git commit -m "conflict fixed"
```
to add and commit the merge.

#### Stash
```git
$ git stash
```
This command can temporarily conceal your 'workbench'. Stashed contents can be recovered by calling
```git
$ git stash pop
``` 
The command
```git
$ git stash list
```
can show you all stashes you have done.
##### When to use stash?
`git stash` is useful when you are in the middle of your dev and you don't want to commit the changes since you haven't done everything yet, and you wish to fix a bug in other branches. 
In this scenario, you want to fix a bug in `master` and you are working on branch `foobar`. First, run `git stash` to conceal everything uncommited in your branch. Then you `git switch master` to work on the `master` branch. After you have done your bugfix and commited all of your changes on the master branch, you `git switch foobar` to continue working on your branch. Run `git stash pop` to reset your workbench.
#### Cherry-pick
But wait! This bug found on the master branch also exists in foobar branch as well! You need to do the same debugging work to your own branch as well!
Suppose the commit id of your commit for bugfix is `6cf3ip9 fix bug`, you can just run
```git
$ git switch foobar
$ git cherry-pick 6cf3ip9
```
To copy that paticular commit to the `foobar` branch! Now the bug has been fixed on both `master` and `foobar`!

#### Tagging
```git
$ git tag v1.0
```
Tag the latest commit on the current branch with tag name `v1.0`.
```git
$ git tag
```
Show all tags.
Tags are sorted in ALPHABETICAL order, NOT in time order.
```git
$ git tag v1.0 f482ck0
```
Tag the commit with commit id `f482ck0` on the current branch with tag name `v1.0`.
```git
$ git show v1.0
```
Show the detailed info of tag `v1.0`
```git
$ git tag -a v0.1 -m "version 0.1 released" x2c91y6
```
\*\*Tag the commit with commit id `x2c91y6` with tag name `v0.1` and tag description `version 0.1 released`
```git
$ git tag -d v0.1
```
Delete a tag called `v0.1`
```git
$ git push origin --tags
```
Push all tags to remote.
