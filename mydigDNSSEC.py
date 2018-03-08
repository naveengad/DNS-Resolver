from __future__ import print_function
import sys
import dns
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

class mydigDNSSEC():
    def __init__(self):
        self.rootservers = [ '198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4']
        self.rootservers += ['198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']                      
        self.timeout = 10
        self.zonecount = 0
        self.errorflag = False
        self.KSK = None 
        self.nodnssec = False

    def dns_resolve(self, qname, rdtype):
        self.set_zonecount(qname)
        resp = self.dns_query(qname, rdtype, self.rootservers, 1)
        if self.errorflag:
            print("DNSSec verification failed")
        elif self.nodnssec:
            print("DNSSEC not supported")
        else:
            if resp:
                self.print_response(resp)
            elif resp == None:
                print("DNSSEC not supported")           
    
    def set_zonecount(self, name):        
        self.zonecount = len(dns.name.from_text(name).labels)

    def print_response(self, result):
        print("Verified IP address")
        if result[0].answer:            
            for item in result[len(result) - 1].answer:
                for rr in item:
                    print(rr.address)

    def dns_query(self, name, rdtype, rootservers, indx): 
        qname = dns.name.from_text(name)   
        while indx <= self.zonecount:
            zone = str(qname.split(indx)[1])
            zonename = dns.name.from_text(zone)       
            for addr in rootservers:                
                try:                    
                    msg = dns.message.make_query(qname, rdtype, want_dnssec=True)
                    rrec = dns.query.tcp(msg, addr, self.timeout)
                    msg = dns.message.make_query(zonename, 48, want_dnssec=True)
                    rsec = dns.query.tcp(msg, addr, self.timeout)
                    if rsec.answer: 
                        if rrec.authority and rrec.authority[1]:
                            for rrset in rrec.authority[1]:
                                if rrset.rdtype in [dns.rdatatype.NSEC3]:
                                    self.nodnssec = True
                                    return False                     
                        ZSK = rsec.answer[0]
                        try:
                            if not self.validate(rsec.answer[0], rsec.answer[1], {zonename:ZSK}):                               
                                return None                      
                            if rrec.answer:
                                if not self.validate(rrec.answer[0], rrec.answer[1], {zonename:ZSK}):
                                    return None                          
                            elif rrec.authority:
                                if not self.validate(rrec.authority[1], rrec.authority[2], {zonename:ZSK}):                          
                                    return None
                        except Exception as e:
                            return None
                    else:
                        return None
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
                                        final_resp = self.dns_query(CNAME, rdtype, self.rootservers, 1)
                                        res += final_resp
                                return res
                            else:
                                if resp.additional:
                                    addrlist = []
                                    for rrset in resp.additional:
                                        if rrset.rdtype in [dns.rdatatype.A]:
                                            for item in rrset:
                                                try:
                                                    if self.verify_ksk(resp.authority[0].name, addr, item.address):
                                                        addrlist.append(item.address)
                                                    elif self.errorflag == True:
                                                        return False
                                                except Exception as e:
                                                    continue
                                    if addrlist:
                                        self.set_zonecount(name)
                                        resp = self.dns_query(name, rdtype, addrlist, indx + 1) 
                                        if resp: return resp
                                        elif resp == False: return False
                                        else: continue
                                    else: 
                                        continue                                   
                                elif resp.authority:
                                    nsaddrlist = []
                                    for rrset in resp.authority:
                                        for rr in rrset.items:
                                            nsaddrlist.append(str(rr))                                
                                    for nsaddr in nsaddrlist:
                                        addrlist = []
                                        for addrtype in ['A']:
                                            self.nodnssec = False
                                            r = self.dns_query(nsaddr, addrtype, self.rootservers, 1) 
                                            if r:
                                                for rrset in r[0].answer:
                                                    for rr in rrset:
                                                        self.nodnssec = False
                                                        try:
                                                            if self.verify_ksk(resp.authority[0].name, addr, rr.address):
                                                                addrlist.append(rr.address)
                                                            elif self.errorflag == True:
                                                                return False
                                                        except Exception as e:
                                                            continue
                                                        #addrlist.append(rr.address)                                            
                                            if addrlist:
                                                self.set_zonecount(name)
                                                resp =  self.dns_query(name, rdtype, addrlist, indx + 1) 
                                                if resp: return resp
                                                elif resp == False: return False 
                                    else:
                                        if self.nodnssec == True:
                                            return False                                    
                                        continue   
                    except Exception as e:
                        continue          
                    else:
                        continue
                except Exception as e:            
                    continue
                i += 1
            else:
                return None
                
    def validate(self, rrset, rrsig, keys):
        try:
            dns.dnssec.validate(rrset, rrsig, keys)
            return True
        except Exception as e:
            return False

    def verify_ksk(self, name, parent_addr, child_addr):
        try:
            msg = dns.message.make_query(name, 43, want_dnssec=True)
            ds_rsp = dns.query.tcp(msg, parent_addr, self.timeout)
            msg = dns.message.make_query(name, 48, want_dnssec=True)
            ksk_rsp = dns.query.tcp(msg, child_addr, self.timeout)
            if not ksk_rsp.answer or not ds_rsp.answer:
                return False
            child_KSK = self.getKSK(ksk_rsp.answer[0].items)
            if not child_KSK:
                return False       
            algorithm = None        
            items = ds_rsp.answer[0].items
            for i in range(len(items)):
                for key in child_KSK:
                    if items[i].digest_type == 1:
                        algorithm = 'SHA1'
                    elif items[i].digest_type==2:
                        algorithm = 'SHA256'
                    ds = dns.dnssec.make_ds(name, key, algorithm) 
                    if ds.digest == items[i].digest:
                        return True 
            self.errorflag = True              
            return False        
        except Exception as e:
            return False

    def getKSK(self, ksk_resp):
        KSK = []
        for key in ksk_resp:            
            if key.flags == 257:
                KSK.append(key)
        return KSK
        
if __name__ == "__main__":
    qname = sys.argv[1]
    rdtype = sys.argv[2]
    dns_resol = mydigDNSSEC()
    dns_resol.dns_resolve(qname, rdtype)