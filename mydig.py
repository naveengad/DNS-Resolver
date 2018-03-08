from __future__ import print_function
import sys
import dns
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time
import datetime

class mydig():
    def __init__(self):
        self.rootservers = [ '198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4']
        self.rootservers += ['198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']              
        self.timeout = 3        

    def dns_resolve(self, qname, rdtype):
        dt = datetime.datetime.now()
        t1 = time.time()
        resp = self.dns_query(qname, rdtype, self.rootservers)
        if not resp: 
            print("Query cannot be resolved")
            return
        t2 = time.time()
        total_time = t2 - t1
        self.print_response(resp, total_time, dt)

    def print_response(self, result, time, dt):        
        print('QUESTION SECTION: ')
        for item in result[0].question:
            print(item)
        if result[0].answer:
            print('\nANSWER SECTION: ')          
            if len(result) == 1:
                for item in result[0].answer:
                        print(item)
            else:               
                for i in range(0, len(result)):
                    for item in result[i].answer:
                            print(item)
        else:
            print('\nAUTHORITY SECTION')
            if len(result) == 1:
                for item in result[0].authority:
                        answer = True
                        print(item)
            else:               
                for i in range(0, len(result)):
                    for item in result[i].authority:
                        answer = True
                        print(item)
        print('\nQuery time: ', str(round(time * 1000)) + ' msec')
        s = str(dt).split(' ')
        d = s[0].split('-')
        t = s[1].split('.')
        print('WHEN: ', dt.strftime("%A")[:3], dt.strftime("%B")[:3], d[2], t[0], d[0])
        print('MSG SIZE rcvd: ', sys.getsizeof(result))

    def dns_query(self, name, rdtype, rootservers):  
        qname = dns.name.from_text(name)                 
        for addr in rootservers:
            try:                    
                msg = dns.message.make_query(qname, rdtype)
                resp = dns.query.udp(msg, addr, self.timeout)                
                respcode = resp.rcode()
                if respcode == 0:
                    if resp.flags & dns.flags.AA == 1024:                        
                        res = [resp]
                        for ans in resp.answer:                            
                            if ans.rdtype == 5:
                                CNAME = str(ans.items[0].target)
                                final_resp = self.dns_query(CNAME, rdtype, self.rootservers)
                                res += final_resp
                        return res
                    else:
                        if resp.additional:
                            addrlist = []
                            for rrset in resp.additional:
                                if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                                    for item in rrset:
                                        addrlist.append(item.address)
                            return self.dns_query(name, rdtype, addrlist)
                        elif resp.authority:
                            nsaddrlist = []
                            for rrset in resp.authority:
                                for rr in rrset.items:
                                    nsaddrlist.append(str(rr))
                            addrlist = []
                            for nsaddr in nsaddrlist:
                                for addrtype in ['A', 'AAAA']:
                                    r = self.dns_query(nsaddr, addrtype, self.rootservers) 
                                    for rrset in r[0].answer:
                                        for rr in rrset:
                                            addrlist.append(rr.address)
                            return self.dns_query(name, rdtype, addrlist)                        
                else:
                    #print('\nError in resolving domain name. Trying again with different address.')
                    continue
            except Exception as e:
                #print("\nQuery failed", e)                
                continue
        else:
            #print('no root server worked')
            return None

if __name__ == "__main__":
    qname = sys.argv[1]
    rdtype = sys.argv[2]
    dns_resol = mydig()
    dns_resol.dns_resolve(qname, rdtype)

