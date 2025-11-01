require 'socket'

server = TCPServer.new("0.0.0.0", 8080)

puts "Running ruby http server: port=8080, process_id=" + Process.pid().to_s

loop do
  client = server.accept

  request_line = client.readline
  method_token, target, version_number = request_line.split

  case [method_token, target]
  when ["GET", "/ping"]
    response_status_code = "200 OK"
    content_type = "text/plain"
    response_message = "PONG!"

  else
    response_status_code = "200 OK"
    response_message =  "✅ Received a #{method_token} request to #{target} with #{version_number}"
    content_type = "text/plain"
  end

  # puts response_message

  # Construct the HTTP Response
  http_response = <<~MSG
    #{version_number} #{response_status_code}
    Content-Type: #{content_type}; charset=#{response_message.encoding.name}
    Location: /ping

    #{response_message}
  MSG

  client.puts http_response
  client.close
end