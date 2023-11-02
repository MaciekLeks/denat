# simple http server bind to ipv6 addr on port 80
`sudo socat TCP6-LISTEN:80,bind=[fd0c:41e9:207b:5400:d740:627c:a774:5131],fork EXEC:'/bin/echo -e "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/plain\r\n\r\nWelcome"'`
