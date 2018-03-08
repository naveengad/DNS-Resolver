# DNS-Resolver
Implemented DNS Resolver which takes input DNS query and translates the domain into IP address. Further extended the implementation to support DNSSEC protocol.
 * mydig.py: Part A DNS resolver code
 * mydigDNSSEC.py: Part B DNSSec resolver code
 * Report.pdf: Contains the part C i.e, CDF result and explanation
 * mydig_output.txt:Contains the output of A, NS, MX 
 * DNSSec implementation.pdf: Contains the procedure followed in DNSSec resolver 

# Dependencies:
- Python 2.7 or 3.x Later
- Install the dnspython and pycrypto

# Command to run the code 
python mydig.py <name> <type>
Example: python mydig.py www.google.com A
python mydigDNSSEC.py <name> <type
Example: python mydigDNSSEC.py verisigninc.com A

