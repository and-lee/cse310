import dns.resolver
from datetime import datetime
import sys

# mydig
# input = name of domain to resolve
# default resolve = "A"
# ex: mydig www.cnn.com
default_root = 'A'
default_root_ip = "198.41.0.4" # IP Address of root server 'A'
url = str(sys.argv[1])
print("QUESTION SECTION:")
print(url + ".\t\tIN\t" + default_root)
print()

# recursively make queries for contacting a server, starting from the root server
# then search through all the top-level domain name servers and
# stop once the authoritative name server is reached, and return the IP address found.
def resolver(dname: str, ip: str, result: str) :
    query = dns.message.make_query(dname, dns.rdataclass.IN) # create a query
    response = dns.query.udp(query, ip, timeout = 2) # get a response
    if(response.answer) :
        # received the ip from the authoritative name server
        if(response.get_rrset(response.answer, response.answer[0].name, dns.rdataclass.IN, dns.rdatatype.A)!=None) :
            answer = response.find_rrset(response.answer, response.answer[0].name, dns.rdataclass.IN, dns.rdatatype.A)
            result += "\t".join(answer.to_text().split()[0:5])
            return result
        else : # CNAME
            answer = response.find_rrset(response.answer, response.answer[0].name, dns.rdataclass.IN, dns.rdatatype.CNAME)
            result += "\t".join(answer.to_text().split()[0:5]) + "\n"
            dname = answer.to_text().split()[4]
            ip = default_root_ip
            return resolver(dname, ip, result) # iterate through another dns request for CNAME
    else :
        if(not response.additional) :
            if(response.get_rrset(response.authority, response.authority[0].name, dns.rdataclass.IN, dns.rdatatype.SOA)!=None) :
                authority = response.get_rrset(response.authority, response.authority[0].name, dns.rdataclass.IN, dns.rdatatype.SOA)
                if(authority.to_text().split()[0]=='.') :
                    return "Invalid Input" # if url does not exist

            authority = response.find_rrset(response.authority, response.authority[0].name, dns.rdataclass.IN, dns.rdatatype.NS)
            result += "\t".join(authority.to_text().split()[0:5]) + "\n"
            dname = authority.to_text().split()[4]
            ip = default_root_ip
            return resolver(dname, ip, result) # iterate through another dns request for the NS (name server)
        else :
            additional = response.find_rrset(response.additional, response.additional[0].name, dns.rdataclass.IN, dns.rdatatype.A)
            ip = additional.to_text().split()[4]
            return resolver(dname, ip, result) # go to the next top-level-domain server

# RRset :
# AUTHORITY = DNS
# ADDITIONAL = IP address(es)

when = datetime.now().strftime("%m/%d/%y %H:%M:%S") # current date and time
start_time = datetime.now() # get start time before query
dig = resolver(url, default_root_ip, "") # resolve
qtime = (datetime.now() - start_time) # total time of query
qtime = qtime.total_seconds() * 1000 # milli seconds
print("ANSWER SECTION:")
print(dig)
print("Query time: " + str(qtime) + " msec")
print("WHEN: " + when)