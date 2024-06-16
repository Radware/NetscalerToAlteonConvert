import NS_to_ALT
from printer_config import *

FILENAME = input("[+]Please make sure netscaler configuration file is at the same folder as this script, and type here the name including the extention - e.i : netclaser_config.txt   ")


alteon_object, net_scaler = NS_to_ALT.convert(FILENAME)

configuration_file_path = net_scaler.get_alteon_config_file()
unhandled_lines_file_path = net_scaler.get_unhandled_lines_file_path()
unhandled_flags_path = net_scaler.get_unhandled_flags_path()
handled_lines_file_path = net_scaler.get_handled_lines_file_path()

print("[+]Processing Real Server configuration")
for real_server in alteon_object.list_all_real_servers():
    write_to_alteon_config(configuration_file_path,print_real_server(real_server))
print("[*]Finished Processing Real Server configuration")

print("[+]Processing FQDN configuration")
for fqdn_server in alteon_object.list_all_fqdns():
    write_to_alteon_config(configuration_file_path,print_fqdn_server(fqdn_server))
print("[*]Finished Processing FQDN configuration")

print("[+]Processing Group configuration")
for group in alteon_object.list_all_groups():
    write_to_alteon_config(configuration_file_path,print_group(group))
print("[*]Finished Processing Group configuration")

print("[+]Processing Health checks monitor configuration")
for hc in alteon_object.list_all_monitors():
    write_to_alteon_config(configuration_file_path,print_hc(hc))
print("[*]Finished Processing Health checks monitor configuration")

print("[+]Processing Pre-defined TCP Policy configuration")
write_to_alteon_config(configuration_file_path,pre_define_tcp_pol())
print("[*]Finished Processing Pre-defined TCP Policy configuration")

print("[+]Processing Pre-defined SSL Policy configuration")
write_to_alteon_config(configuration_file_path,pre_define_ssl_pol())
print("[*]Finished Processing Pre-defined SSL Policy configuration")

print("[+]Processing VIRT configuration")
for virt in alteon_object.list_all_virts():
    write_to_alteon_config(configuration_file_path,print_virt(virt))
print("[*]Finished Processing VIRT  configuration")

print("[+]Processing Service configuration")
for service in alteon_object.list_all_services():
    write_to_alteon_config(configuration_file_path,print_service(service))
print("[*]Finished Processing Service configuration")

uniquify_lines_in_file(net_scaler.get_unhandled_flags_path())
write_to_unhandled_lines(FILENAME,handled_lines_file_path,unhandled_lines_file_path)