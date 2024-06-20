import logging
from materials import *
import printer_config
import pdb


class Netscaler:

    def __init__(self, configuration_file_path, unhandled_lines_file_path,
                 unhandled_flags_path,
                 handled_lines_file_path,alteon_config_file):
        self.configuration_file_path = configuration_file_path
        self.unhandled_lines_file_path = unhandled_lines_file_path
        self.unhandled_flags_path = unhandled_flags_path
        self.handled_lines_file_path = handled_lines_file_path
        self.alteon_config_file = alteon_config_file

        # class properties
        self.bind_lb_vserver_no_policy_list = []
        self.add_lb_vserver_virt_list = []
        self.add_serviceGroup_list = []
        self.add_service_list = []
        self.bind_serviceGroup_no_monitor_list = []
        self.bind_service_no_monitor_list = []
        self.bind_lb_vserver_with_policy_list = []
        self.bind_ssl_profile_vserver_list = []
        self.add_ssl_profile_list = []
        self.add_server_list = []
        self.add_server_fqdn_list = []
        self.add_responder_policy_list = []
        self.add_responder_action_list = []
        self.bind_ssl_vserver_list = []
        self.link_ssl_certKey_list = []
        self.monitor_list = []



        # Logger configuration
        self.logger = logging.getLogger('Netscaler')
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler('netscaler.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.add_lb_vserver_service_type = {
                                                "HTTP": "supported",
                                                "FTP": "supported",
                                                "TCP": "supported",
                                                "UDP": "supported",
                                                "SSL": "supported",
                                                "SSL_BRIDGE": "supported",
                                                "SSL_TCP": "supported",
                                                "DTLS": "supported",
                                                "NNTP": "supported",
                                                "DNS": "supported",
                                                "DHCPRA": "supported",
                                                "ANY": "supported",
                                                "SIP_UDP": "supported",
                                                "SIP_TCP": "supported",
                                                "SIP_SSL": "supported",
                                                "DNS_TCP": "supported",
                                                "RTSP": "supported",
                                                "PUSH": "supported",
                                                "SSL_PUSH": "supported",
                                                "RADIUS": "supported",
                                                "RDP": "supported",
                                                "MYSQL": "supported",
                                                "MSSQL": "supported",
                                                "DIAMETER": "supported",
                                                "SSL_DIAMETER": "supported",
                                                "TFTP": "supported",
                                                "ORACLE": "supported",
                                                "SMPP": "supported",
                                                "SYSLOGTCP": "supported",
                                                "SYSLOGUDP": "supported",
                                                "FIX": "supported",
                                                "SSL_FIX": "supported",
                                                "PROXY": "supported",
                                                "USER_TCP": "supported",
                                                "USER_SSL_TCP": "supported",
                                                "QUIC": "supported",
                                                "IPFIX": "supported",
                                                "LOGSTREAM": "supported",
                                                "MONGO": "supported",
                                                "MONGO_TLS": "supported",
                                                "MQTT": "supported",
                                                "MQTT_TLS": "supported",
                                                "QUIC_BRIDGE": "supported",
                                                "HTTP_QUIC": "supported"
                                        }
        self.persistency_types_alteon_supported = {
                                                    'CALLID': 'unsupported',
                                                   'SOURCEIP': 'supported',
                                                   'COOKIEINSERT': 'supported',
                                                   'URLPASSIVE': 'supported',
                                                   'SRCIPDESTIP': 'unsupported',
                                                   'RULE': 'unsupported',
                                                   'CUSTOMSERVERID': 'unsupported',
                                                   'DESTIP': 'unsupported',
                                                   'RTSPSID': 'unsupported',
                                                   'FIXSESSION': 'unsupported',
                                                   'USERSESSION': 'unsupported',
                                                   'NONE': 'supported',
                                                   'SSLSESSION':'supported'}

        self.lb_method_types_alteon_supported = {
                                                'ROUNDROBIN': 'supported',
                                                'LEASTCONNECTION': 'supported',
                                                'LEASTRESPONSETIME': 'supported',
                                                'URLHASH': 'unsupported',
                                                'DOMAINHASH': 'unsupported',
                                                'DESTINATIONIPHASH': 'unsupported',
                                                'SOURCEIPHASH': 'supported',
                                                'SRCIPDESTIPHASH': 'unsupported',
                                                'LEASTBANDWIDTH': 'supported',
                                                'LEASTPACKETS': 'unsupported',
                                                'TOKEN': 'unsupported',
                                                'SRCIPSRCPORTHASH': 'supported',# but on persistency
                                                'LRTM': 'unsupported',
                                                'CALLIDHASH': 'unsupported',
                                                'CUSTOMLOAD': 'unsupported',
                                                'LEASTREQUEST': 'unsupported',
                                                'AUDITLOGHASH': 'unsupported',
                                                'STATICPROXIMITY': 'unsupported',
                                                'USER_TOKEN': 'unsupported'
                                                    }

        self.add_lb_vserver_unsupported_flags = {
                                                '-persistenceBackup': "'persistenceBackup' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-backupPersistenceTimeout': "'backupPersistenceTimeout' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-hashLength': "'hashLength' flag related to LB method is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-backupLBMethod': "'backupLBMethod' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-rule': "'rule' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-Listenpolicy': "'Listenpolicy' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-listenPriority': "'listenPriority' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-resRule': "'resRule' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-rtspNat': "'rtspNat' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-m': "'m' flag for redirection mode in load balancing is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-tosId': "'tosId' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dataLength': "'dataLength' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dataOffset': "'dataOffset' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-sessionless': "'sessionless' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-trofsPersistence': "'trofsPersistence' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-connfailover': "'connfailover' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-redirectURL': "'redirectURL' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-cacheable': "'cacheable' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-soMethod': "'soMethod' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-soPersistence': "'soPersistence' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-soPersistenceTimeOut': "'soPersistenceTimeOut' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-healthThreshold': "'healthThreshold' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-soThreshold': "'soThreshold' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-soBackupAction': "'soBackupAction' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-redirectPortRewrite': "'redirectPortRewrite' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-downStateFlush': "'downStateFlush' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-disablePrimaryOnDown': "'disablePrimaryOnDown' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-insertVserverIPPort': "'insertVserverIPPort' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-vipHeader': "'vipHeader' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-AuthenticationHost': "'AuthenticationHost' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-Authentication': "'Authentication' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-authn401': "'authn401' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-authnVsName': "'authnVsName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-push': "'push' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-pushVserver': "'pushVserver' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-pushLabel': "'pushLabel' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-pushMultiClients': "'pushMultiClients' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dbProfileName': "'dbProfileName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-l2Conn': "'l2Conn' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-oracleServerVersion': "'oracleServerVersion' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-mssqlServerVersion': "'mssqlServerVersion' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-mysqlProtocolVersion': "'mysqlProtocolVersion' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-mysqlServerVersion': "'mysqlServerVersion' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-mysqlCharacterSet': "'mysqlCharacterSet' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-mysqlServerCapabilities': "'mysqlServerCapabilities' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-appflowLog': "'appflowLog' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-icmpVsrResponse': "'icmpVsrResponse' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-RHIstate': "'RHIstate' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-newServiceRequest': "'newServiceRequest' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-newServiceRequestUnit': "'newServiceRequestUnit' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-newServiceRequestIncrementInterval': "'newServiceRequestIncrementInterval' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-minAutoscaleMembers': "'minAutoscaleMembers' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-persistAVPno': "'persistAVPno' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-skippersistency': "'skippersistency' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-td': "'td' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-authnProfile': "'authnProfile' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-macmodeRetainvlan': "'macmodeRetainvlan' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dbsLb': "'dbsLb' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dns64': "'dns64' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-bypassAAAA': "'bypassAAAA' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-RecursionAvailable': "'RecursionAvailable' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-processLocal': "'processLocal' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-dnsProfileName': "'dnsProfileName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-lbprofilename': "'lbprofilename' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-redirectFromPort': "'redirectFromPort' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-httpsRedirectUrl': "'httpsRedirectUrl' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-retainConnectionsOnCluster': "'retainConnectionsOnCluster' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-adfsProxyProfile': "'adfsProxyProfile' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-quicBridgeProfilename': "'quicBridgeProfilename' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-probeProtocol': "'probeProtocol' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-probeSuccessResponseCode': "'probeSuccessResponseCode' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-probePort': "'probePort' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-toggleorder': "'toggleorder' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                '-orderthreshold': "'orderthreshold' flag is not supported by the converter tool. Please consult Radware documentation for alternatives."
                                                  }


        self.add_lb_vserver_supported_flags = {
                                                '-timeout': 'persistenceTimeout',
                                                '-netmask': 'lbMethodHashMak',
                                                '-v6netmasklen': 'lbMethodHashMakipv6',
                                                '-cookieName': 'insertCookieName',
                                                '-persistMask': 'persistMask',
                                                '-v6persistmasklen': 'v6persistmasklen',
                                                '-state': 'state',
                                                '-cltTimeout': 'cltTimeout',
                                                '-tcpProfileName': 'tcpProfileName',
                                                '-httpProfileName': 'httpProfileName',
                                                '-comment': 'comment',
                                                '-netProfile': 'netProfile',
                                                '-quicProfileName': 'quicProfileName'
                                            }

        self.bind_lb_vserver_unsupported_flags = {
                                                'weight': "'weight' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'policyName': "'policyName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'priority': "'priority' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'gotoPriorityExpression': "'gotoPriorityExpression' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'type': "'type' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'invoke': "'invoke' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'labelType': "'labelType' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'labelName': "'labelName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'analyticsProfile': "'analyticsProfile' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                'order': "'order' flag is not supported by the converter tool. Please consult Radware documentation for alternatives."
                                            }

        self.add_service_group_unsupported_flags ={
                                                "serviceType": "'serviceType' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "cacheType": "'cacheType' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "td": "'td' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "maxClient": "'maxClient' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "maxReq": "'maxReq' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "cacheable": "'cacheable' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "cip": "'cip' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "cipHeader": "'cipHeader' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "usip": "'usip' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "pathMonitor": "'pathMonitor' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "pathMonitorIndv": "'pathMonitorIndv' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "useproxyport": "'useproxyport' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "healthMonitor": "'healthMonitor' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "sp": "'sp' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "rtspSessionidRemap": "'rtspSessionidRemap' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "cltTimeout": "'cltTimeout' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "svrTimeout": "'svrTimeout' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "CKA": "'CKA' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "TCPB": "'TCPB' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "CMP": "'CMP' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "maxBandwidth": "'maxBandwidth' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "monThreshold": "'monThreshold' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "state": "'state' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "downStateFlush": "'downStateFlush' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "tcpProfileName": "'tcpProfileName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "httpProfileName": "'httpProfileName' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "comment": "'comment' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "appflowLog": "'appflowLog' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "netProfile": "'netProfile' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "autoScale": "'autoScale' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "memberPort": "'memberPort' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "autoDisablegraceful": "'autoDisablegraceful' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "autoDisabledelay": "'autoDisabledelay' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "autoDelayedTrofs": "'autoDelayedTrofs' flag is not supported by the converter tool. Please consult Radware documentation for alternatives.",
                                                "monConnectionClose": "'monConnectionClose' flag is not supported by the converter tool. Please consult Radware documentation for alternatives."
        }
        # you may refer to the tools txt file to see the flag brief explanation
        self.add_servicegroup_backend_flags = {
                                        "serviceGroupName": "unsupported",
                                        "serviceType": "unsupported",
                                        "-cacheType": "supported",
                                        "-td": "unsupported",
                                        "-maxClient": "supported",
                                        "-maxReq": "supported",
                                        "-cacheable": "supported",
                                        "-cip": "unsupported",
                                        "-cipHeader": "unsupported",
                                        "-usip": "supported",
                                        "-pathMonitor": "unsupported",
                                        "-pathMonitorIndv": "unsupported",
                                        "-useproxyport": "unsupported",
                                        "-healthMonitor": "unsupported",
                                        "-sp": "unsupported",
                                        "-rtspSessionidRemap": "unsupported",
                                        "-cltTimeout": "supported",
                                        "-svrTimeout": "supported",
                                        "-CKA": "supported",
                                        "-TCPB": "supported",
                                        "-CMP": "supported",
                                        "-maxBandwidth": "supported",
                                        "-monThreshold": "unsupported",
                                        "-state": "supported",
                                        "-downStateFlush": "unsupported",
                                        "-tcpProfileName": "supported",
                                        "-httpProfileName": "unsupported",
                                        "-comment": "supported",
                                        "-appflowLog": "unsupported",
                                        "-netProfile": "unsupported",
                                        "-autoScale": "unsupported",
                                        "-memberPort": "unsupported",
                                        "-autoDisablegraceful": "unsupported",
                                        "-autoDisabledelay": "unsupported",
                                        "-autoDelayedTrofs": "unsupported",
                                        "-monConnectionClose": "unsupported"
}

    def get_alteon_config_file(self):
        return self.alteon_config_file

    def get_configuration_file_path(self):
        """Return configuration_file_path which created while giving the name of the Net Scaler config file to handle"""
        return self.configuration_file_path

    def get_unhandled_lines_file_path(self):
        """Return unhandled_lines_file_path which created while giving the name of the Net Scaler config file
         to handle"""
        return self.unhandled_lines_file_path

    def get_unhandled_flags_path(self):
        """Return unhandled_flags_path which created while giving the name of the Net Scaler config file to handle"""
        return self.unhandled_flags_path

    def get_handled_lines_file_path(self):
        """Return handled_lines_file_path which created while giving the name of the Net Scaler config file to handle"""
        return self.handled_lines_file_path

    def net_scaler_file_validator(self):
        """Validate the integrity of Net Scaler configuration"""
        pass

    def read_file(self):
        """Read Net Scaler CLI configuration file, Text file is expected"""
        try:
            with open(self.configuration_file_path, "r") as file:
                file_list = file.readlines()
                return file_list
        except Exception as e:
            self.logger.error(f"Error reading file {self.configuration_file_path}: {e}")
        return []

    def get_bind_lb_vserver_no_policy_list(self):
        return self.bind_lb_vserver_no_policy_list

    def get_add_lb_vserver_virt_list(self):
        return self.add_lb_vserver_virt_list

    def get_add_serviceGroup_list(self):
        return self.add_serviceGroup_list

    def get_add_service_list(self):
        return self.add_service_list

    def get_bind_serviceGroup_no_monitor_list(self):
        return self.bind_serviceGroup_no_monitor_list

    def get_bind_service_no_monitor_list(self):
        return self.bind_service_no_monitor_list

    def get_bind_lb_vserver_with_policy_list(self):
        return self.bind_lb_vserver_with_policy_list

    def get_bind_ssl_profile_vserver_list(self):
        return self.bind_ssl_profile_vserver_list

    def get_add_ssl_profile_list(self):
        return self.add_ssl_profile_list

    def get_add_server_list(self):
        return self.add_server_list

    def get_add_server_fqdn_list(self):
        return self.add_server_fqdn_list

    def get_add_responder_policy_list(self):
        return self.add_responder_policy_list

    def get_add_responder_action_list(self):
        return self.add_responder_action_list

    def get_bind_ssl_vserver_list(self):
        return self.bind_ssl_vserver_list

    def get_link_ssl_certKey_list(self):
        return self.link_ssl_certKey_list

    def get_monitor_list(self):
        return self.monitor_list

    def handle_add_lb_vserver(self, line):
        add_lb_vserver_virt_dict = {}
        split_line = line.split(" ")
        add_lb_vserver_virt_dict["virt_name"] = split_line[3].strip()
        add_lb_vserver_virt_dict["service_type"] = split_line[4].strip()
        if validate_ipv4(split_line[5].strip()) or validate_ipv6(split_line[5].strip()):
            add_lb_vserver_virt_dict["virt_ip"] = split_line[5].strip()
        add_lb_vserver_virt_dict["service_port"] = split_line[6].strip()
        for index, item in enumerate(split_line):
            if index > 6 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                add_lb_vserver_virt_dict[flag] = flag_value
        self.add_lb_vserver_virt_list.append(add_lb_vserver_virt_dict)
        return add_lb_vserver_virt_dict

    def handle_bind_lb_vserver_no_policy(self, line):
        bind_lb_vserver_no_policy_dict = {}
        split_line = line.split(" ")
        bind_lb_vserver_no_policy_dict["virt_name"] = split_line[3].strip()
        bind_lb_vserver_no_policy_dict["service_name"] = split_line[4].strip()
        self.bind_lb_vserver_no_policy_list.append(bind_lb_vserver_no_policy_dict)
        return bind_lb_vserver_no_policy_dict

    def handle_add_serviceGroup(self, line):
        add_serviceGroup_dict = {}
        split_line = line.split(" ")
        add_serviceGroup_dict["service_name"] = split_line[2].strip()
        add_serviceGroup_dict["service_type"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                if "client_ip_header" in add_serviceGroup_dict:
                    if flag == add_serviceGroup_dict["client_ip_header"]:
                        continue
                if flag == "cip" and flag_value == "ENABLED":
                    add_serviceGroup_dict["client_ip_header"] = split_line[index + 2].strip()
                add_serviceGroup_dict[flag] = flag_value
        self.add_serviceGroup_list.append(add_serviceGroup_dict)
        return add_serviceGroup_dict

    def handle_add_service(self, line):
        add_service_dict = {}
        bind_service_group = {}
        bind_service_no_monitor_dict= {}
        split_line = line.split(" ")
        add_service_dict["service_name"] = split_line[2].strip()
        add_service_dict["service_type"] = split_line[4].strip()
        add_service_dict["port"] = split_line[5].strip()
        if validate_ipv4(split_line[3].strip()) or validate_ipv6(split_line[3].strip()):
            bind_service_no_monitor_dict["server"] = split_line[3].strip()
            bind_service_no_monitor_dict["port"] = split_line[5].strip()
            bind_service_no_monitor_dict["service_name"] = split_line[2].strip()
            self.bind_service_no_monitor_list.append(bind_service_no_monitor_dict)
        bind_service_group['service_name'] = split_line[2].strip()
        bind_service_group['service_member'] = split_line[3].strip()
        bind_service_group['port'] = split_line[5].strip()
        self.bind_serviceGroup_no_monitor_list.append(bind_service_group)
        for index, item in enumerate(split_line):
            if index > 5 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                if "client_ip_header" in add_service_dict:
                    if flag == add_service_dict["client_ip_header"]:
                        continue
                if flag == "cip" and flag_value == "ENABLED":
                    add_service_dict["client_ip_header"] = split_line[index + 2].strip()
                add_service_dict[flag] = flag_value
        self.add_serviceGroup_list.append(add_service_dict)
        return add_service_dict

    def handle_bind_serviceGroup_no_monitor(self, line):
        bind_serviceGroup_no_monitor_dict = {}
        split_line = line.split(" ")
        bind_serviceGroup_no_monitor_dict["service_name"] = split_line[2].strip()
        bind_serviceGroup_no_monitor_dict["service_member"] = split_line[3].strip()
        bind_serviceGroup_no_monitor_dict["port"] = split_line[4].strip()
        for index, item in enumerate(split_line):
            if index > 4 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                bind_serviceGroup_no_monitor_dict[flag] = flag_value
        self.bind_serviceGroup_no_monitor_list.append(bind_serviceGroup_no_monitor_dict)
        return bind_serviceGroup_no_monitor_dict

    def handle_bind_service_no_monitor(self, line):
        bind_service_no_monitor_dict = {}
        split_line = line.split(" ")
        bind_service_no_monitor_dict["service_name"] = split_line[2].strip()
        bind_service_no_monitor_dict["service_member"] = split_line[3].strip()
        bind_service_no_monitor_dict["port"] = split_line[4].strip()
        for index, item in enumerate(split_line):
            if index > 4 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                bind_service_no_monitor_dict[flag] = flag_value
        self.bind_service_no_monitor_list.append(bind_service_no_monitor_dict)
        return bind_service_no_monitor_dict

    def handle_bind_lb_vserver_with_policy(self, line):
        bind_lb_vserver_with_policy_dict = {}
        split_line = line.split(" ")
        bind_lb_vserver_with_policy_dict["virt_name"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                bind_lb_vserver_with_policy_dict[flag] = flag_value
        self.bind_lb_vserver_with_policy_list.append(bind_lb_vserver_with_policy_dict)
        return bind_lb_vserver_with_policy_dict

    def handle_bind_ssl_profile_vserver(self, line):
        bind_ssl_profile_vserver_dict = {}
        split_line = line.split(" ")
        bind_ssl_profile_vserver_dict["virt_name"] = split_line[3].strip()
        bind_ssl_profile_vserver_dict["ssl_profile_id"] = split_line[5].strip()
        self.bind_ssl_profile_vserver_list.append(bind_ssl_profile_vserver_dict)
        return bind_ssl_profile_vserver_dict

    def handle_add_ssl_profile(self, line):
        add_ssl_profile_dict = {}
        split_line = line.split(" ")
        add_ssl_profile_dict["ssl_profile_name"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                add_ssl_profile_dict[flag] = flag_value
        self.add_ssl_profile_list.append(add_ssl_profile_dict)
        return add_ssl_profile_dict

    def handle_add_server(self, line):
        add_server_dict = {}
        split_line = line.split(" ")
        add_server_dict["server_name"] = split_line[2].strip()
        add_server_dict["ip_address"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                add_server_dict[flag] = flag_value
        self.add_server_list.append(add_server_dict)
        return add_server_dict

    def handle_add_server_fqdn(self, line):
        add_server_fqdn_dict = {}
        split_line = line.split(" ")
        add_server_fqdn_dict["server_name"] = split_line[2].strip()
        add_server_fqdn_dict["fqdn"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                add_server_fqdn_dict[flag] = flag_value
        self.add_server_fqdn_list.append(add_server_fqdn_dict)
        return add_server_fqdn_dict

    def handle_add_responder_policy(self, line):
        add_responder_policy_dict = {}
        split_line = line.split(" ")
        add_responder_policy_dict["policy_name"] = split_line[3].strip()
        if split_line[4].startswith('"') and split_line[4].endswith('"'):
            add_responder_policy_dict["policy_expression"] = split_line[4].strip()
        add_responder_policy_dict["policy_action"] = split_line[5].strip()
        for index, item in enumerate(split_line):
            if index > 4 and "-" in item:
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                add_responder_policy_dict[flag] = flag_value
        self.add_responder_policy_list.append(add_responder_policy_dict)
        return add_responder_policy_dict

    def handle_add_responder_action(self, line):
        add_responder_action_dict = {}
        split_line = line.split(" ")
        add_responder_action_dict["policy_action_name"] = split_line[3].strip()
        actions_lst = []
        for index, item in enumerate(split_line):
            if index > 3:
                actions_lst.append(item.strip())
        actions = ''.join(actions_lst)
        add_responder_action_dict["actions"] = actions
        self.add_responder_action_list.append(add_responder_action_dict)
        return add_responder_action_dict

    def handle_bind_ssl_vserver(self, line):
        bind_ssl_vserver_dict = {}
        split_line = line.split(" ")
        bind_ssl_vserver_dict["virt_name"] = split_line[3].strip()
        for index, item in enumerate(split_line):
            if index > 3 and item.startswith("-"):
                flag = item.strip("-")
                flag_value = split_line[index + 1].strip()
                bind_ssl_vserver_dict[flag] = flag_value
        self.bind_ssl_vserver_list.append(bind_ssl_vserver_dict)
        return bind_ssl_vserver_dict

    def handle_link_ssl_certKey(self, line):
        link_ssl_certKey_dict = {}
        split_line = line.split(" ")
        link_ssl_certKey_dict["cert_name"] = split_line[3].strip()
        link_ssl_certKey_dict["inter_cert_name"] = split_line[4].strip()
        self.link_ssl_certKey_list.append(link_ssl_certKey_dict)
        return link_ssl_certKey_dict

    def handle_add_lb_monitor(self, line):
        """Parse Netscaler file for Health checks information to the returned dictionary"""
        try:
            printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
            parts = line.split()
            monitor_dict = {}
            monitor_dict['monitorName'] = parts[3].strip('"').strip("'")
            monitor_dict['type'] = parts[4]
            i = 5
            while i < len(parts):
                flag = parts[i]
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    value = parts[i + 1]
                    i += 2
                else:
                    value = None
                    i += 1

                if value and (value.startswith('"') or value.startswith("'")):
                    while not value.endswith('"') and not value.endswith("'") and i < len(parts):
                        value += f" {parts[i]}"
                        i += 1
                    value = value.strip('"').strip("'")

                if value:
                    monitor_dict[flag.lstrip('-')] = value
                else:
                    monitor_dict[flag.lstrip('-')] = True

            self.monitor_list.append(monitor_dict)
            return monitor_dict
        except Exception as e:
            self.logger.error(f"Error parsing monitor line: {line}. Error: {e}")

    def slb_config_extract(self, file_in_list):
        """Gets the lines of the  netscaler configuration as list, Go over the list,
         if is match for the line - extract the info and put into list"""
        for line in file_in_list:
            if is_add_lb_vserver_virt(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_lb_vserver(line)

            if is_bind_lb_vserver_no_policy(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_bind_lb_vserver_no_policy(line)

            if is_add_serviceGroup(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_serviceGroup(line)

            if is_add_service(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_service(line)

            if is_bind_serviceGroup_no_monitor(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_bind_serviceGroup_no_monitor(line)

            if is_bind_service_no_monitor(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_bind_service_no_monitor(line)

            if is_bind_lb_vserver_with_policy(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_bind_lb_vserver_with_policy(line)

            if is_bind_ssl_profile_vserver(line):
                self.handle_bind_ssl_profile_vserver(line)

            if is_add_ssl_profile(line):
                self.handle_add_ssl_profile(line)

            if is_add_server(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_server(line)

            if is_add_server_fqdn(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_server_fqdn(line)

            if is_add_responder_policy(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_responder_policy(line)

            if is_add_responder_action(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_responder_action(line)

            if is_bind_ssl_vserver(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_bind_ssl_vserver(line)

            if is_link_ssl_certKey(line):
                #printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_link_ssl_certKey(line)

            if is_add_lb_monitor(line):
                printer_config.write_to_handled_lines(self.handled_lines_file_path, line)
                self.handle_add_lb_monitor(line)

