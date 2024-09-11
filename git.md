# Git howtos
## Howto restore an accidentally deleted file
Look for the commit where the file was last present. Note the commit hash

...
git log -- myfile
...


Restore it:

...
git checkout <commit-hash> -- myfile
...
