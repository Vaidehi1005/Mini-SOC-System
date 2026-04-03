import socket

target = "127.0.0.1"

for i in range(50):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target, 80))
    except:
        pass
    s.close()