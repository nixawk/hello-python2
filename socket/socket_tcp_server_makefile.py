import socket
ADDR = ("localhost", 12345)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(ADDR)
listener.listen(1)

print "server on: %s:%s" % ADDR

while True:
    cli, addr = listener.accept()
    fr = cli.makefile('r+b', bufsize=0)
    fw = cli.makefile('w+b', bufsize=0)

    fw.write('data back to client')
    fw.flush()

    data = fr.read()
    cli.close()
    print data
