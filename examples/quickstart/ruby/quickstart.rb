# Simple web service that just returns Ok to any path.
require 'socket'

# Initialize a TCPServer object that will listen
# on localhost:2345 for incoming connections.
server = TCPServer.new('localhost', 8080)

STDOUT.puts "Listening on http://localhost:8080"

loop do
  # Wait until a client connects
  socket = server.accept
  request = socket.gets
  STDOUT.puts request

  response = "Hello World!\n"
  socket.print "HTTP/1.1 200 OK\r\n" +
                 "Content-Type: text/plain\r\n" +
                 "Content-Length: #{response.bytesize}\r\n" +
                 "Connection: close\r\n"
  socket.print "\r\n"
  socket.print response
  socket.close
end