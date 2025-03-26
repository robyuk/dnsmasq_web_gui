This Python web server uses only built-in libraries to read and display the dnsmasq.leases file. It also displays the reserved IP address details, and allows you to add IP address reservations.

Here's a breakdown of how it works:

It creates a custom HTTP request handler that extends SimpleHTTPRequestHandler to process requests
The server handles two routes:

/ - A simple homepage with a link to the connected devices page
/connected_devices - Displays the parsed leases file as an HTML table
/reserved_ip - Displays reserved IP address details
/reserve_ip - Add a reserved IP address


For the connected devices page, the server:

Reads the /var/lib/misc/dnsmasq.leases file
Parses each line into its component fields
Converts the timestamp (first field) from Unix time to a human-readable format (YYYY/MM/DD HH)
Displays the MAC address, IP address, and hostname in a formatted HTML table
Skips the fifth field (01-MAC) as requested


The server includes basic error handling for cases where:

The leases file doesn't exist
There's an error reading or parsing the file
The timestamp can't be converted



To run the server:

Save the code to a file (e.g., dnsmasq_web_gui.py)
Make it executable: chmod +x dnsmasq_web_gui.py
Run it: ./dnsmasq_web_gui.py.py
Access the server in your browser at http://localhost:8000

The server will run until you stop it with Ctrl+C. You can modify the port in the run_server function if port 8000 is already in use.

The page at /reserved_ip does this:

Reads /etc/dnsmasq.conf
Parses all dhcp-host entries using a regular expression
Extracts the MAC address, IP address, and hostname
Displays them in a formatted HTML table
Skips comment lines (lines starting with #)
Ignores any comments at the end of valid lines (after #)

Added proper error handling if the configuration file can't be found or read

The server now provides a complete web interface to view both currently connected devices and permanently reserved IP addresses in your DNSMasq configuration.

I've made the following key modifications to the original script:

Added a new /reserve_ip route for both GET and POST methods
Created a new method serve_reserve_ip_form() to generate the HTML form
Implemented handle_ip_reservation() to process the form submission
Added comprehensive validation methods:

validate_mac_address(): Normalizes and validates MAC addresses
validate_ip_address(): Checks IP address against DHCP ranges and existing leases
validate_hostname(): Validates hostname according to RFC 1123

Added add_reservation_to_config() to write the reservation to the dnsmasq.conf file

Key validation features include:

MAC Address: Normalization to standard format, hex digit check, duplicate check
IP Address: Format validation, DHCP range check, lease/reservation conflict check
Hostname: Length, character set, and structural validation
Error handling with descriptive messages
Successful reservation confirmation

Note: This script assumes it will be run with sufficient permissions to modify the dnsmasq configuration file. In a production environment, you might want to add additional security checks and potentially use a more robust method of updating configurations.
A few important considerations:

The script requires root/sudo permissions to modify /etc/dnsmasq.conf
You may need to restart the dnsmasq service for changes to take effect
Error handling is included to prevent invalid entries
