import socket

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Waiting for connection...")

conn, addr = server.accept()
print(f"Connected by {addr}")

data = conn.recv(1024).decode()
print("Message from Pi:", data)

# send ACK
conn.sendall("ACK".encode())
print("ACK sent")

conn.close()
server.close()