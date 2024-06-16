# NetScaler to Alteon configuration converter

This tool read basic CLI configuration file of Net Scaler load balancer,
And turn it into Alteon basic CLI configuration.

At this Second version, we would like to produce a tool that convert mass and repeatedly 
configuration such as backend servers, service and service group and vserver Health monitors and SSL 
certificates to try ease for a mass configuration files of netscaler. 

More than a helper for a mass configuration, this tool is define the structure of how should the 
configuration from netscaler need to be interpreter to Alteon.


## Note

Use this tool at your own risk, this tool aim to help with massive configuration sets,
This tool not replacing Network Engineer, this tool is not cover layer 3 and layer 2 and Traffic domain
configurations.

#### For this current version, there is no cover for Traffic Domains(-td).

This tool written and tested for CLI configuration of NetScaler version 14.X and Alteon version 33.0.X.

### Building Blocks of the system

- main.py - which feed with NetScaler configuration file 
- printer_config.py -  is incharge of creating files project and print the configuration on Alteon CLI Style
- NS_to_ALT.py - takes netscaler class object and turn it into Alteon class
- Alteon.py - Alteon class which contains other classes 
- real_server.py , group.py, service.py, virt.py, health_check.py -  are the classes which define the different components of Alteon class.
- netscaler.py - reads netscaler configuration file and output dictionaries to pass to NS_to_ALT.py
- materials.py - contains functions and attributes that help for integrity 
- ssl-policy.py -  for future version of this tool, will be the class contains the ssl attributes.

### Functionality of this tool

main.py triggers printer_config.py (gets file path) starts new project and initiate convert method.
netscaler.py class get the file, process it and output dictionary for NS_to_ALT.py which handle the returned dictionary and cast it into Alteon object.
once we have alteon object we print the configuration using getters of alteon class.


### Not supported

- Layer 2 configuration
- Layer 3 configuration
- vserver with "ANY" service type
- Support for Traffic Domain
- support TLS policies
- support for HTTP options

### Supported features
#### Note: Netscaler feature name in parentheses 

- Real Server (Server) 
- FQDN Server (FQDN)
- Group (N/A)
- load balancing algorithms (Round-Robin, Least Connection, SourceIPHASH, Least response-time, Least bandwidth)
- persistence configurations (SOURCEIP,COOKIEINSERT,SSLSESSION)
- Service (Service / Service Group)
- VIRT (Vserver)
- FTP Support control and data port
- Redirect from HTTP to HTTPS (Response policy) , XFF insert (USIP).
- Health Checks: TCP ,UDP ,ICMP, ARP, HTTP\S.
- certificate and keys convert - on a particular additional script.

### Roadmap
#### version 3
- SSL policies 
- TCP Profile
- More HTTP features and http profile
- HTTP-3
- Support for Traffic Domain
- Layer 7 policies support

## Output after activating the tool

Starting this tool will trigger creation of folder name consist of the date and the NS configuration
Name.
Inside the folder there should be 4 files:

1.alteon_config.txt - configuration of alteon after convert process

2.handled_lines.txt - output of the lines of NS configuration this tool processed

3.unhandled_lines.txt - output of the lines of NS configuration this tool didn't process

4.unhandled_flags.txt - output the features and the values of the feature this tool not
converted

## Tool to convert certificate to alteon
### Note - this is additional simple tool and not part of the main system
1. Edit the file "netscalet_to_alt_cert_migration.py" change the path to the file text which will be the results on parameter "CertsConfForAlteon"
2. Edit the file "netscalet_to_alt_cert_migration.py" change the path to the certificate files exported from netscaler on parameter "cert_dir"
3. Run the script: "python netscalet_to_alt_cert_migration.py"
4. Copy the content of the result text file 
5. connect to the alteon using SSH
6. Type "verbose 0" to enter to insert configuration mode
7. past the text file content
8. Type "verbose 1" to exit the insert configuration mode
9. Type "apply" and then "save"


## How to Use the tool?
1. copy the project to your local machine
2. run "main.py" , you will be asked to provide the path to netscaler configuration file
3. My advice is -  put the configuration file within the same folder as the script to avoid playing with the path.
4. Run the file and take a look on the results
5. running the file should create folder inside the folders project with 4 files
6. handled_lines.txt - these are the lines that has been taken to be converted.
7. unhandled_lines.txt -  lines ignored by the script
8. unhandled_flags.txt -  line that was covered but there was a feature that was unsupported
9. alteon_config.txt - The result of the tool
10. Copy the content of the result text file 
11. connect to the alteon using SSH
12. Type "verbose 0" to enter to insert configuration mode
13. past the text file content
14. Type "verbose 1" to exit the insert configuration mode
15. Type "apply" and then "save"

For any concern, feedback, request and etc.. you always welcome to speak with me : tomerel@radware.com
# NetscalerToAlteonConvert
