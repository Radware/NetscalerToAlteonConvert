import Alteon
from health_check import *
from virt import Virt
from group import Group
from real_server import *
from service import Service

alteon_class_instance = Alteon.Alteon() # create new alteon instance

# Real Server class tests
real_server_instance = RealServer("this_is_real_server", "10.20.30.40")  # Create new Real server instance
print(real_server_instance.get_ip_address())  # Print IP address
print(real_server_instance.get_name())  # Print name

# Test setting a new IP address
try:
    real_server_instance.set_ip_address("192.168.1.1")
    print(f"New IP address: {real_server_instance.get_ip_address()}")
except ValueError as e:
    print(f"Error: {e}")

# Test setting a new name
real_server_instance.set_name("new_real_server_name")
print(f"New name: {real_server_instance.get_name()}")

# Test getting and setting state
print(f"Initial state: {real_server_instance.get_state()}")
real_server_instance.set_state("dis")
print(f"New state: {real_server_instance.get_state()}")

# Test getting and setting comment
print(f"Initial comment: {real_server_instance.get_comment()}")
real_server_instance.set_comment("This is a test comment")
print(f"New comment: {real_server_instance.get_comment()}")

print("=====================================================================")
# FQDN class tests
fqdn_instance = Fqdn("fqdn1", "example.com")  # Create new FQDN instance
print(fqdn_instance.get_fqdn_domain())  # Print FQDN domain
print(fqdn_instance.get_fqdn_id())  # Print FQDN ID

# Test setting a new FQDN domain
try:
    fqdn_instance.set_fqdn_domain("newexample.com")
    print(f"New FQDN domain: {fqdn_instance.get_fqdn_domain()}")
except ValueError as e:
    print(f"Error: {e}")

# Test setting a new FQDN ID
fqdn_instance.set_fqdn_id("fqdn2")
print(f"New FQDN ID: {fqdn_instance.get_fqdn_id()}")

# Test getting and setting state
print(f"Initial state: {fqdn_instance.get_state()}")
fqdn_instance.set_state("dis")
print(f"New state: {fqdn_instance.get_state()}")

# Test getting and setting IP version
print(f"Initial IP version: {fqdn_instance.get_ip_version()}")
fqdn_instance.set_ip_version("v6")
print(f"New IP version: {fqdn_instance.get_ip_version()}")

# Test getting and setting TTL
print(f"Initial TTL: {fqdn_instance.get_ttl()}")
fqdn_instance.set_ttl(3600)
print(f"New TTL: {fqdn_instance.get_ttl()}")

print("=========================Health check============================================")

helath_check_instance = TCPMonitor(tcp_id="new_tcp_hc_id")
print(helath_check_instance.get_tcp_id())
print("=========================Group============================================")

group_instance = Group(group_id="new_Group_id_instance")
group_instance.add_real_server(real_server_instance)
group_instance.set_health_check(helath_check_instance)
print(group_instance.list_all_real_servers())
print(group_instance.get_health_check())

print("=========================Service============================================")
new_service = Service(virtual_server_id="service_instance",
                      application="HTTP",
                      service_port=80,
                      protocol="TCP",
                      action="group",
                      group_id="new_Group_id_instance")
print(new_service.get_group_id())
print(new_service.get_virtual_server_id())
print(new_service.get_service_port())
print(new_service.get_protocol())
print(new_service.get_action())
print(new_service.get_group_id())

print("=========================Virt============================================")
new_virt = Virt(virtual_server_id="new_virt",
                ip_address="1.2.3.4",
                services=[new_service])

alteon_class_instance.add_real_server(real_server_instance)
alteon_class_instance.add_group(group_instance)
alteon_class_instance.add_service(new_service)
alteon_class_instance.add_monitor(helath_check_instance)
alteon_class_instance.add_virt(new_virt)
alteon_class_instance.list_all_attributes()