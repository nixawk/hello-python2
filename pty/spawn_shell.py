
# http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# http://netsec.ws/?p=337

# import pty; pty.spawn("/bin/sh")

import pty


pty.spawn("/bin/bash")
