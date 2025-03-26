#! /bin/env /usr/bin/python3

import http.server
import socketserver
import datetime

# Define the port on which the server will listen
PORT = 8000

# Path to the dnsmasq leases file
#LEASES_FILE = '/var/lib/misc/dnsmasq.leases'
LEASES_FILE = 'dnsmasq.leases'
CONFIG_FILE = 'dnsmasq.conf'

class ConnectedDevicesHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/connected_devices':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Read the leases file
            with open(LEASES_FILE, 'r') as file:
                leases = file.readlines()

            # Start the HTML response
            self.wfile.write(b'<html><head><title>Connected Devices</title></head>')
            self.wfile.write(b'<body><h1>Connected Devices</h1><table border="1">')
            self.wfile.write(b'<tr><th>Connected Since</th><th>MAC Address</th><th>IP Address</th><th>Hostname</th></tr>')

            # Process each line in the leases file
            for lease in leases:
                fields = lease.split()
                connected_since = datetime.datetime.fromtimestamp(int(fields[0])).strftime('%Y/%m/%d %H:%M')
                mac_address = fields[1]
                ip_address = fields[2]
                hostname = fields[3]
                ext_mac = fields[4]

                # Write the device information to the HTML table
                self.wfile.write(f'<tr><td>{connected_since}</td><td>{mac_address}</td><td>{ip_address}</td><td>{hostname}</td></tr>'.encode())

            # End the HTML response
            self.wfile.write(b'</table></body></html>')
        else:
            # Handle other paths
            self.send_error(404, "File Not Found")

# Set up the HTTP server
with socketserver.TCPServer(("", PORT), ConnectedDevicesHandler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()