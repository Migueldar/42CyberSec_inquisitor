import socket

host = '172.18.0.2'
port = 60002
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.connect((host, port))
	s.send(b'hola')
	s.send(b'\n')