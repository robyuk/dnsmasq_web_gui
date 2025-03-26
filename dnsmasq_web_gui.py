#!/usr/bin/env python3
import http.server
import socketserver
import os
import time
import datetime
import html
import re
import urllib.parse
import ipaddress


class DNSMasqServerHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler to display dnsmasq information and handle IP reservations
    """

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/connected_devices':
            self.serve_connected_devices()
        elif self.path == '/reserved_ip':
            self.serve_reserved_ip()
        elif self.path == '/reserve_ip':
            self.serve_reserve_ip_form()
        else:
            # Serve a simple homepage with links
            self.serve_homepage()

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/reserve_ip':
            self.handle_ip_reservation()
        else:
            # Default to method not allowed
            self.send_response(405)
            self.end_headers()

    def serve_homepage(self):
        """Serve a simple homepage with navigation"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        response = """<!DOCTYPE html>
        <html>
        <head>
            <title>DNSMasq Server</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                h1 { color: #333; }
                a { color: #0066cc; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>DNSMasq Server</h1>
            <p>Welcome to the DNSMasq Server Web GUI.</p>
            <ul>
                <li><a href="/connected_devices">View Connected Devices</a></li>
                <li><a href="/reserved_ip">View Reserved IP Addresses</a></li>
                <li><a href="/reserve_ip">Reserve a New IP Address</a></li>
            </ul>
        </body>
        </html>
        """
        self.wfile.write(response.encode())

    def serve_reserve_ip_form(self):
        """Serve the IP reservation form"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        response = """<!DOCTYPE html>
        <html>
        <head>
            <title>Reserve IP Address</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                form { max-width: 500px; margin: 0 auto; }
                label { display: block; margin-top: 10px; }
                input { width: 100%; padding: 5px; margin-top: 5px; }
                .error { color: red; }
                .success { color: green; }
                .btn { 
                    background-color: #0066cc; 
                    color: white; 
                    padding: 10px; 
                    border: none; 
                    cursor: pointer; 
                    margin-top: 10px; 
                }
            </style>
        </head>
        <body>
            <h1>Reserve IP Address</h1>
            <form action="/reserve_ip" method="post">
                <label for="mac_address">MAC Address:</label>
                <input type="text" id="mac_address" name="mac_address" placeholder="00:11:22:33:44:55" required>

                <label for="ip_address">IP Address:</label>
                <input type="text" id="ip_address" name="ip_address" placeholder="192.168.1.100" required>

                <label for="hostname">Hostname:</label>
                <input type="text" id="hostname" name="hostname" placeholder="device-name" required>

                <label for="comments">Comments (Optional):</label>
                <input type="text" id="comments" name="comments">

                <input type="submit" value="Reserve IP" class="btn">
            </form>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        """
        self.wfile.write(response.encode())

    def handle_ip_reservation(self):
        """Handle IP reservation form submission"""
        # Read the form data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = urllib.parse.parse_qs(post_data)

        # Extract form fields
        mac_address = form_data.get('mac_address', [''])[0].strip()
        ip_address = form_data.get('ip_address', [''])[0].strip()
        hostname = form_data.get('hostname', [''])[0].strip()
        comments = form_data.get('comments', [''])[0].strip()

        # Validate inputs
        validation_errors = []

        # MAC Address Validation
        try:
            normalized_mac = self.validate_mac_address(mac_address)
        except ValueError as e:
            validation_errors.append(str(e))

        # IP Address Validation
        try:
            validated_ip = self.validate_ip_address(ip_address)
        except ValueError as e:
            validation_errors.append(str(e))

        # Hostname Validation
        try:
            validated_hostname = self.validate_hostname(hostname)
        except ValueError as e:
            validation_errors.append(str(e))

        # If there are validation errors, return an error response
        if validation_errors:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            error_html = """<!DOCTYPE html>
            <html>
            <head>
                <title>IP Reservation Error</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                    .error { color: red; }
                </style>
            </head>
            <body>
                <h1>IP Reservation Failed</h1>
                <div class="error">
                    <h2>The following errors were found:</h2>
                    <ul>
            """
            for error in validation_errors:
                error_html += f"<li>{html.escape(error)}</li>"

            error_html += """
                    </ul>
                </div>
                <p><a href="/reserve_ip">Try Again</a> | <a href="/">Home</a></p>
            </body>
            </html>
            """
            self.wfile.write(error_html.encode())
            return

        # If all validations pass, add the reservation to dnsmasq.conf
        try:
            self.add_reservation_to_config(normalized_mac, validated_ip, validated_hostname, comments)



        except Exception as e:
            # Handle any errors in adding reservation
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            error_html = f"""<!DOCTYPE html>
            <html>
            <head>
                <title>Reservation Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                    .error {{ color: red; }}
                </style>
            </head>
            <body>
                <h1>IP Reservation Failed</h1>
                <div class="error">
                    <p>An error occurred while adding the reservation:</p>
                    <p>{html.escape(str(e))}</p>
                </div>
                <p><a href="/reserve_ip">Try Again</a> | <a href="/">Home</a></p>
            </body>
            </html>
            """
            self.wfile.write(error_html.encode())
            return

        # Successful reservation

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        success_html = """<!DOCTYPE html>
         <html>
         <head>
             <title>IP Reservation Successful</title>
             <style>
                 body {{font - family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                 .success {{ color: green; }}
             </style>
         </head>
         <body>
             <h1>IP Reservation Successful</h1>
             <div class="success">
                 <p>The IP address has been successfully reserved.</p>
                 <p>Details:</p>
                 <ul>
                     <li>MAC Address: {mac}</li>
                     <li>IP Address: {ip}</li>
                     <li>Hostname: {hostname}</li>
                 </ul>
             </div>
             <p>
                 <a href="/reserve_ip">Reserve Another IP</a> | 
                 <a href="/reserved_ip">View Reserved IPs</a> | 
                 <a href="/">Home</a>
             </p>
         </body>
         </html>
         """.format(
            mac=html.escape(normalized_mac),
            ip=html.escape(validated_ip),
            hostname=html.escape(validated_hostname)
        )
        self.wfile.write(success_html.encode())
        return


    def validate_mac_address(self, mac):
        """
        Validate and normalize MAC address
        - Normalize to 00:11:22:33:44:55 format
        - Check exactly 12 hex digits
        - Ensure no existing reservations in dnsmasq.conf have this MAC
        """
        # Remove any existing separators and convert to lowercase
        mac_stripped = re.sub(r'[:-]', '', mac.lower())

        # Check if exactly 12 hex digits
        if not re.match(r'^[0-9a-f]{12}$', mac_stripped):
            raise ValueError("Invalid MAC address. Must be 12 hexadecimal characters.")

        # Normalize to standard format
        normalized_mac = ':'.join(mac_stripped[i:i + 2] for i in range(0, 12, 2))

        # Check for existing reservations
        conf_file_path = '/etc/dnsmasq.conf'
        conf_file_path = 'dnsmasq.conf'  # TESTING
        try:
            with open(conf_file_path, 'r') as file:
                for line in file:
                    # Match dhcp-host entries
                    match = re.search(r'dhcp-host=([^,]+)', line)
                    if match and mac_stripped in match.group(1).replace(':', '').lower():
                        raise ValueError(f"MAC address {normalized_mac} is already reserved.")
        except FileNotFoundError:
            pass  # Ignore if config file doesn't exist

        return normalized_mac

    def validate_ip_address(self, ip):
        """
        Validate IP address:
        - Check standard IPv4 format
        - Check not already in reserved IPs or leases (with some exceptions)
        - Validate against DNSMasq-served subnets
        """
        # Validate basic IP format
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            raise ValueError("Invalid IP address format.")

        # Validate against DHCP ranges in dnsmasq.conf
        conf_file_path = '/etc/dnsmasq.conf'
        conf_file_path = 'dnsmasq.conf'  # TESTING
        valid_range = False

        try:
            with open(conf_file_path, 'r') as file:
                for line in file:
                    # Look for dhcp-range entries
                    match = re.search(r'dhcp-range=([^,]+),([^,]+)', line)
                    if match:
                        try:
                            start_ip = ipaddress.IPv4Address(match.group(1))
                            end_ip = ipaddress.IPv4Address(match.group(2))

                            # Check if IP is within the range
                            if start_ip <= ip_obj <= end_ip:
                                valid_range = True
                                break
                        except ValueError:
                            # Skip invalid range entries
                            continue
        except FileNotFoundError:
            raise ValueError("Could not find dnsmasq configuration file.")

        # If not in any valid DHCP range, prompt for confirmation
        if not valid_range:
            raise ValueError("IP address is outside the configured DHCP ranges.")

        # Check against existing leases and reserved IPs
        leases_file_path = '/var/lib/misc/dnsmasq.leases'
        leases_file_path = 'dnsmasq.leases'  # TESTING
        try:
            with open(leases_file_path, 'r') as file:
                for lease in file:
                    fields = lease.strip().split()
                    if len(fields) >= 3 and fields[2] == ip:
                        raise ValueError(f"IP address {ip} is already in use in leases.")
        except FileNotFoundError:
            pass

        # Validate against existing reserved IPs
        conf_file_path = '/etc/dnsmasq.conf'
        conf_file_path = 'dnsmasq.conf'  # TESTING
        try:
            with open(conf_file_path, 'r') as file:
                for line in file:
                    # Match dhcp-host entries with IP
                    match = re.search(r'dhcp-host=[^,]+,([^,]+)', line)
                    if match and match.group(1) == ip:
                        raise ValueError(f"IP address {ip} is already reserved.")
        except FileNotFoundError:
            pass

        return ip

    def validate_hostname(self, hostname):
        """
        Validate hostname:
        - 1-63 characters
        - Start/end with letter/number
        - Can contain letters, numbers, hyphens
        - No consecutive hyphens
        """
        # Check length
        if len(hostname) < 1 or len(hostname) > 63:
            raise ValueError("Hostname must be 1-63 characters long.")

        # RFC 1123 validation
        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', hostname):
            raise ValueError("Invalid hostname. Must start/end with letter/number, no consecutive hyphens.")

        return hostname

    def add_reservation_to_config(self, mac, ip, hostname, comments=''):
        """
        Add the reservation to dnsmasq.conf
        """
        conf_file_path = '/etc/dnsmasq.conf'
        conf_file_path = 'dnsmasq.conf'  # TESTING

        # Prepare the dhcp-host entry
        dhcp_host_entry = f"dhcp-host={mac},{ip},{hostname}"
        if comments:
            dhcp_host_entry += f" # {comments}"

        # Attempt to add to configuration
        try:
            with open(conf_file_path, 'a') as file:
                file.write(f"\n{dhcp_host_entry}\n")
        except Exception as e:
            raise ValueError(f"Could not write to configuration file: {str(e)}")


    def serve_connected_devices(self):
        """Parse and display the dnsmasq.leases file as a formatted HTML table"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Path to the dnsmasq.leases file
        #leases_file_path = '/var/lib/misc/dnsmasq.leases'
        leases_file_path = 'dnsmasq.leases'  # TESTING

        # Start building the HTML response
        response = """<!DOCTYPE html>
        <html>
        <head>
            <title>Connected Devices</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                h1 { color: #333; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                .refresh { margin-bottom: 20px; }
                a { color: #0066cc; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>Connected Devices</h1>
            <div class="refresh">
                <a href="/connected_devices">Refresh</a> | 
                <a href="/reserved_ip">Reserved IPs</a> | 
                <a href="/">Home</a>
            </div>
        """

        # Check if the file exists
        if not os.path.exists(leases_file_path):
            response += """
            <p>Error: The dnsmasq.leases file could not be found at /var/lib/misc/dnsmasq.leases</p>
            </body>
            </html>
            """
            self.wfile.write(response.encode())
            return

        # Try to read and parse the file
        try:
            with open(leases_file_path, 'r') as file:
                leases = file.readlines()

            # Start the table
            response += """
            <table>
                <tr>
                    <th>Connected Since</th>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                </tr>
            """

            # Process each line in the leases file
            for lease in leases:
                fields = lease.strip().split()

                # Check if the line has enough fields
                if len(fields) >= 5:
                    # Parse the timestamp and convert to human-readable format
                    try:
                        timestamp = int(fields[0])
                        date_time = datetime.datetime.fromtimestamp(timestamp)
                        formatted_date = date_time.strftime('%Y/%m/%d %H:%M')
                    except ValueError:
                        formatted_date = "Invalid timestamp"

                    # Extract the other fields
                    mac_address = html.escape(fields[1])
                    ip_address = html.escape(fields[2])
                    hostname = html.escape(fields[3])

                    # Add a row to the table
                    response += f"""
                    <tr>
                        <td>{formatted_date}</td>
                        <td>{mac_address}</td>
                        <td>{ip_address}</td>
                        <td>{hostname}</td>
                    </tr>
                    """

            # Close the table
            response += """
            </table>
            <p><small>Last updated: {}</small></p>
            """.format(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

        except Exception as e:
            # Handle any errors
            response += f"""
            <p>Error reading or parsing the dnsmasq.leases file: {html.escape(str(e))}</p>
            """

        # Close the HTML
        response += """
        </body>
        </html>
        """

        self.wfile.write(response.encode())

    def serve_reserved_ip(self):
        """Parse and display the dhcp-host entries from dnsmasq.conf file"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Path to the dnsmasq.conf file
        #conf_file_path = '/etc/dnsmasq.conf'
        conf_file_path = 'dnsmasq.conf'  ## TESTING

        # Start building the HTML response
        response = """<!DOCTYPE html>
        <html>
        <head>
            <title>Reserved IP Addresses</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                h1 { color: #333; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                .refresh { margin-bottom: 20px; }
                a { color: #0066cc; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>Reserved IP Addresses</h1>
            <div class="refresh">
                <a href="/reserved_ip">Refresh</a> | 
                <a href="/connected_devices">Connected Devices</a> | 
                <a href="/">Home</a>
            </div>
        """

        # Check if the file exists
        if not os.path.exists(conf_file_path):
            response += """
            <p>Error: The dnsmasq.conf file could not be found at /etc/dnsmasq.conf</p>
            </body>
            </html>
            """
            self.wfile.write(response.encode())
            return

        # Try to read and parse the file
        try:
            # Read the configuration file
            with open(conf_file_path, 'r') as file:
                conf_lines = file.readlines()

            # Start the table
            response += """
            <table>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                </tr>
            """

            # Regular expression to match dhcp-host entries
            # Format: dhcp-host=<MAC address>,<IP Address>,<Hostname>,<01-MAC> [# Comment]
            #dhcp_host_regex = r'^dhcp-host=([^,]+),([^,]+),([^,]+)(?:,[^#]*)?\s*(?:#.*)?$'
            dhcp_host_regex = r'^dhcp-host=([^,]+),([^,]+),([^,]+)(?:,[^#]*)?$'

            # Process each line in the conf file looking for dhcp-host entries
            for line in conf_lines:

                # Skip comment lines
                if line.startswith('#') or not line:
                    continue

                # Strip whitespace
                line = line.strip()

                # Remove comments at the end of the line if any
                if '#' in line:
                    line = line.split('#', 1)[0].strip()

                # Match dhcp-host entries
                match = re.match(dhcp_host_regex, line)
                if match:
                    mac_address = html.escape(match.group(1))
                    ip_address = html.escape(match.group(2))
                    hostname = html.escape(match.group(3))

                    # Add a row to the table
                    response += f"""
                    <tr>
                        <td>{mac_address}</td>
                        <td>{ip_address}</td>
                        <td>{hostname}</td>
                    </tr>
                    """

            # Close the table
            response += """
            </table>
            <p><small>Last updated: {}</small></p>
            """.format(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

        except Exception as e:
            # Handle any errors
            response += f"""
            <p>Error reading or parsing the dnsmasq.conf file: {html.escape(str(e))}</p>
            """

        # Close the HTML
        response += """
        </body>
        </html>
        """

        self.wfile.write(response.encode())


def run_server(port=8000):
    """
    Start the web server on the specified port
    """
    server_address = ('', port)
    httpd = socketserver.TCPServer(server_address, DNSMasqServerHandler)
    print(f"Server started at http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the server...")
        httpd.shutdown()


if __name__ == "__main__":
    # Default port is 8000, but can be changed here
    run_server(8000)