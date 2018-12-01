#/bin/bash

# Tested on Kali Linux

file="psmsf"

if [ -f "$file" ]; then
	sudo cp "$file" "/usr/bin/$file" && echo "install successfully"
else	
    git clone https://github.com/join-us/psmsf "/tmp/$file"
	sudo cp "/tmp/$file/$file" "/usr/bin/$file" && echo "install successfully"
fi
