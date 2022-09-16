https://www.pwndefend.com/2021/09/08/redirecting-traffic-with-socat/


socat TCP4-LISTEN:443,fork TCP4:xx.xx.xx.xx:443

this will redirect all traffic on current machine at 443 to the target (xx.xx.xx.xx) machine at 443

to check 

```python
#!/usr/bin/env python3

import http.server

import ssl

httpd = http.server.HTTPServer((‘0.0.0.0′, 443), http.server.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket, certfile=’../server.pem’, server_side=True)

httpd.serve_forever()
```
