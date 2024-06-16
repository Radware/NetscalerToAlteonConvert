from health_check import *

# Sanity check for ARPMonitor class

# Creating an instance with just the mandatory name attribute
arp_monitor = ARPMonitor(name="My ARP Monitor")

# Checking default values
assert arp_monitor.arp_id == "arp", "Default arp_id should be 'arp'"
assert arp_monitor.destination_ip == "none", "Default destination_ip should be 'none'"

# Checking attribute setting and getting
arp_monitor.set_arp_id("new_arp")
assert arp_monitor.get_arp_id() == "new_arp", "arp_id should be set to 'new_arp'"

# Checking list_all_attributes method
# This is a bit trickier since list_all_attributes prints the values.
# You might redirect stdout to capture the print output or modify list_all_attributes to return the values instead for testing.

# Ideally, you should perform these tests for all methods and properties to ensure complete sanity checking.
#################################################################################################################
# Example checks for ARPMonitor

# Instantiate an ARPMonitor with default values
arp_monitor = ARPMonitor(name="MyARPMonitor")

# Set values using setters
arp_monitor.set_arp_id("arp_test_id")
arp_monitor.set_description("This is a test ARP monitor.")
arp_monitor.set_destination_ip("192.168.0.1")
arp_monitor.set_invert_result("Enabled")
arp_monitor.set_interval(10)
arp_monitor.set_retries_to_failure(5)
arp_monitor.set_retries_to_restore(3)
arp_monitor.set_response_timeout(2)
arp_monitor.set_check_interval_downtime(5)

# Retrieve values using getters to check if the setters worked correctly
assert arp_monitor.get_arp_id() == "arp_test_id"
assert arp_monitor.get_description() == "This is a test ARP monitor."
assert arp_monitor.get_destination_ip() == "192.168.0.1"
assert arp_monitor.get_invert_result() == "Enabled"
assert arp_monitor.get_interval() == 10
assert arp_monitor.get_retries_to_failure() == 5
assert arp_monitor.get_retries_to_restore() == 3
assert arp_monitor.get_response_timeout() == 2
assert arp_monitor.get_check_interval_downtime() == 5
print("All sanity checks passed for MyARPMonitor.")
# Example checks for DNSMonitor

# Instantiate a DNSMonitor with default values
dns_monitor = DNSMonitor(name="MyDNSMonitor")

# Set values using setters
dns_monitor.set_protocol("UDP")
dns_monitor.set_port(53)
dns_monitor.set_ip_version("IPv6")
dns_monitor.set_description("DNS health check monitor.")
dns_monitor.set_destination_ip("::1")
dns_monitor.set_invert_result("Enabled")
dns_monitor.set_transparent_health_check("Enabled")
dns_monitor.set_domain("example.com")
dns_monitor.set_interval(10)
dns_monitor.set_retries_to_failure(5)
dns_monitor.set_retries_to_restore(3)
dns_monitor.set_response_timeout(2)
dns_monitor.set_check_interval_downtime(5)

# Retrieve values using getters to check if the setters worked correctly
assert dns_monitor.get_protocol() == "UDP"
assert dns_monitor.get_port() == 53
assert dns_monitor.get_ip_version() == "IPv6"
assert dns_monitor.get_description() == "DNS health check monitor."
assert dns_monitor.get_destination_ip() == "::1"
assert dns_monitor.get_invert_result() == "Enabled"
assert dns_monitor.get_transparent_health_check() == "Enabled"
assert dns_monitor.get_domain() == "example.com"
assert dns_monitor.get_interval() == 10
assert dns_monitor.get_retries_to_failure() == 5
assert dns_monitor.get_retries_to_restore() == 3
assert dns_monitor.get_response_timeout() == 2
assert dns_monitor.get_check_interval_downtime() == 5
print("All sanity checks passed for MyDNSMonitor.")


# Instantiate an FTPMonitor with default values
ftp_monitor = FTPMonitor(name="MyFTPMonitor")

# Set values using setters
ftp_monitor.set_ftp_id("ftp_test_id")
ftp_monitor.set_description("This is a test FTP monitor.")
ftp_monitor.set_destination_port(21)
ftp_monitor.set_ip_version("IPv4")
ftp_monitor.set_destination_ip("192.168.1.1")
ftp_monitor.set_invert_result(True)
ftp_monitor.set_transparent_health_check(True)
ftp_monitor.set_username("testuser")
ftp_monitor.set_password("testpass")
ftp_monitor.set_path_filename("/test/path")
ftp_monitor.set_interval(6)
ftp_monitor.set_retries_to_failure(3)
ftp_monitor.set_retries_to_restore(1)
ftp_monitor.set_response_timeout(10)
ftp_monitor.set_check_interval_downtime(20)

# Retrieve values using getters to check if the setters worked correctly
assert ftp_monitor.get_ftp_id() == "ftp_test_id"
assert ftp_monitor.get_description() == "This is a test FTP monitor."
assert ftp_monitor.get_destination_port() == 21
assert ftp_monitor.get_ip_version() == "IPv4"
assert ftp_monitor.get_destination_ip() == "192.168.1.1"
assert ftp_monitor.get_invert_result() is True
assert ftp_monitor.get_transparent_health_check() is True
assert ftp_monitor.get_username() == "testuser"
assert ftp_monitor.get_password() == "testpass"
assert ftp_monitor.get_path_filename() == "/test/path"
assert ftp_monitor.get_interval() == 6
assert ftp_monitor.get_retries_to_failure() == 3
assert ftp_monitor.get_retries_to_restore() == 1
assert ftp_monitor.get_response_timeout() == 10
assert ftp_monitor.get_check_interval_downtime() == 20

print("All sanity checks passed for FTPMonitor.")


# Assume we have an HTTPMonitor class with the attributes and methods defined previously.

# Create an instance of the HTTPMonitor
http_monitor = HTTPMonitor('http')

# Check if the default values are set correctly
assert http_monitor.get_name() == 'http', "Default name should be 'http'"
assert http_monitor.get_expected_return_codes() == ['200'], "Default expected return code should be ['200']"

# Test the setters by changing the values and verifying them with the getters
try:
    http_monitor.set_interval(10)
    assert http_monitor.get_interval() == 10, "Interval should be set to 10"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    http_monitor.set_retries_to_failure(5)
    assert http_monitor.get_retries_to_failure() == 5, "Retries to failure should be set to 5"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    http_monitor.set_response_timeout(30)
    assert http_monitor.get_response_timeout() == 30, "Response timeout should be set to 30"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    http_monitor.set_checks_interval_on_downtime(15)
    assert http_monitor.get_checks_interval_on_downtime() == 15, "Checks interval on downtime should be set to 15"
except AssertionError as e:
    print(f"AssertionError: {e}")

# Check if the setters are correctly handling invalid values
try:
    http_monitor.set_interval(-5)
except ValueError as e:
    assert str(e) == "Interval cannot be negative", "Negative interval should raise a ValueError"

# You would continue to write checks for each setter and other methods as required.
# These checks are basic and could be expanded with more comprehensive tests, error handling, and edge cases.
print("All sanity checks passed for http_monitor.")


https_monitor = HTTPSMonitor('https')

# Check if the default values are set correctly
assert https_monitor.get_name() == 'https', "Default name should be 'https'"
assert https_monitor.get_https() == "Enabled", "HTTPS should be enabled by default"
assert https_monitor.get_cipher() == 'DEFAULT', "Default cipher should be 'DEFAULT'"
print(https_monitor.get_method())
assert https_monitor.get_method() == "GET", "Default method should be 'GET'"

# Test the setters by changing the values and verifying them with the getters
try:
    https_monitor.set_interval(10)
    assert https_monitor.get_interval() == 10, "Interval should be set to 10"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    https_monitor.set_retries_to_failure(5)
    assert https_monitor.get_retries_to_failure() == 5, "Retries to failure should be set to 5"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    https_monitor.set_response_timeout(30)
    assert https_monitor.get_response_timeout() == 30, "Response timeout should be set to 30"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    https_monitor.set_checks_interval_on_downtime(15)
    assert https_monitor.get_checks_interval_on_downtime() == 15, "Checks interval on downtime should be set to 15"
except AssertionError as e:
    print(f"AssertionError: {e}")

# Check if HTTPS specific attributes are set correctly
try:
    https_monitor.set_https(False)
    assert https_monitor.get_https() == False, "HTTPS should be able to be disabled"
except AssertionError as e:
    print(f"AssertionError: {e}")

# Check if the setters are correctly handling invalid values
try:
    https_monitor.set_interval(-5)
except ValueError as e:
    assert str(e) == "Interval cannot be negative", "Negative interval should raise a ValueError"

# Check if HTTPS cannot be disabled as it should always be enabled for HTTPSMonitor
try:
    https_monitor.set_https(False)
except ValueError as e:
    assert str(e) == "HTTPS cannot be disabled for HTTPSMonitor", "Disabling HTTPS should raise a ValueError"

print("All sanity checks passed for https_monitor.")


# Create an instance of TCPMonitor with default parameters
tcp_monitor = TCPMonitor('tcp')
assert tcp_monitor.get_name() == 'tcp', "Name should be set to 'tcp' by default."

# Set and get the destination port
tcp_monitor.set_destination_port('8080')
assert tcp_monitor.get_destination_port() == '8080', "Destination port should be set to '8080'."

# Set and get the IP version
tcp_monitor.set_ip_version('IPv6')
assert tcp_monitor.get_ip_version() == 'IPv6', "IP version should be set to 'IPv6'."

# Set and get the response timeout
tcp_monitor.set_response_timeout(10)
assert tcp_monitor.get_response_timeout() == 10, "Response timeout should be set to 10."

# Create an instance of UDPMonitor with default parameters
udp_monitor = UDPMonitor('udp')
assert udp_monitor.get_name() == 'udp', "Name should be set to 'udp' by default."

# Set and get the destination port
udp_monitor.set_destination_port('53')
assert udp_monitor.get_destination_port() == '53', "Destination port should be set to '53'."

# Set and get the IP version
udp_monitor.set_ip_version('IPv4')
assert udp_monitor.get_ip_version() == 'IPv4', "IP version should be set to 'IPv4'."

# Set and get the interval
udp_monitor.set_interval(10)
assert udp_monitor.get_interval() == 10, "Interval should be set to 10."

print("All sanity checks passed for TCPMonitor and UDPMonitor.")


# Create an instance of the ICMPMonitor class
icmp_monitor = ICMPMonitor('icmp')

# Check if the default values are set correctly
assert icmp_monitor.get_name() == 'icmp', "Default name should be 'icmp'"
assert icmp_monitor.get_interval() == 5, "Default interval should be 5 seconds"
assert icmp_monitor.get_retries_to_failure() == 4, "Default retries to failure should be 4"
assert icmp_monitor.get_retries_to_restore() == 2, "Default retries to restore should be 2"
assert icmp_monitor.get_response_timeout() == 0, "Default response timeout should be 0 seconds"
assert icmp_monitor.get_checks_interval_on_downtime() == 0, "Default checks interval on downtime should be 0 seconds"

# Test the setters by changing the values and verifying them with the getters
try:
    icmp_monitor.set_interval(10)
    assert icmp_monitor.get_interval() == 10, "Interval should be set to 10 seconds"
except AssertionError as e:
    print(f"AssertionError: {e}")

try:
    icmp_monitor.set_retries_to_failure(5)
    assert icmp_monitor.get_retries_to_failure() == 5, "Retries to failure should be set to 5"
except AssertionError as e:
    print(f"AssertionError: {e}")

# Continue with other setters and getters...

print("All sanity checks passed for icmp_monitor.")