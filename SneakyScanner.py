import scapy 
import requests
from scapy.all import *

print(""" __  _ ___ _____ _   _  __  ___ _  __    __   ___ __  __  _ __  _ ___ ___   
|  \| | __|_   _| | | |/__\| _ \ |/ /  /' _/ / _//  \|  \| |  \| | __| _ \  
| | ' | _|  | | | 'V' | \/ | v /   <   `._`.| \_| /\ | | ' | | ' | _|| v /  
|_|\__|___| |_| !_/ \_!\__/|_|_\_|\_\  |___/ \__/_||_|_|\__|_|\__|___|_|_\  """)
print("=========================================")

# Helper Method for getting MAC Vendor
def macInfo(mac_address):
    url = "https://api.macvendors.com/"

    response = requests.get(url+mac_address)
    
    if response.status_code == 200:
        return response.content.decode()
    else:
        return "No MAC Vendor Info"
# Helper Method Extracting IPv6 Address
def extractIPv6(input):
    strip = ""
    ip = list(input.split(":"))

    index = 0
    ans = ['' for _ in range(8)]
    flag = 0

    for i in range(len(ip)):
        if len(ip[i]) == 4:
            ans[index] = ip[i]
            index += 1

        elif len(ip[i]) > 0:
            ans[index] = '0' * (4 - len(ip[i])) + ip[i]
            index += 1

        else: # len(ip[i]) == 0
            if flag == 0:
                for j in range(8 - len(ip) + 1):
                    ans[index] = '0000'
                    index += 1
                flag = 1
            else:
                ans[index] = '0000'
                index += 1

    for i in range(len(ans)-1):
        print(ans[i], end=':')
        strip += ans[i] + ":"

    print(ans[-1])
    strip+=ans[-1]
    return strip
# Helper Method for checking IPv6 Stateful or Stateless
def ipv6Check(ipv6):
     x = ipv6.split(":")
     p1 = x[5]
     p2 = x[6]
     if "FF" in p1 and "FE" in p2:
        print("Current IPv6 Address is **STATELESS (EUI64)**")
     else:
        print("Current IPv6 Address is **STATEFUL**")

def networkID(ip,mask):

    network = ''

    iOctets = ip.split('.')
    mOctets = mask.split('.')

    network = str( int( iOctets[0] ) & int(mOctets[0] ) ) + '.'
    network += str( int( iOctets[1] ) & int(mOctets[1] ) ) + '.'
    network += str( int( iOctets[2] ) & int(mOctets[2] ) ) + '.'
    network += str( int( iOctets[3] ) & int(mOctets[3] ) )

    return network

## Code Starts here 

# The current globally routable IPv4 address of the victim-host. 
conf.use_pcap = True
# Local IP Address
ip = get_if_addr(conf.iface)
print("Host's IP Address Info: ", ip)
print()

# Global IP Address
globalIP = requests.get("https://www.wikipedia.org").headers["X-Client-IP"]
print("Host's Global IP Address Info: ", globalIP)
print()
# The MAC address associated with (i.e., assigned to) the victim-host interface from A).
mac = get_if_hwaddr(conf.iface)
print("Host's MAC Address is ", mac)
print()

# The IPv6 address assigned to victim-host interface from A) – if available.
ipv6 = get_if_addr6(conf.iface)
if ipv6 is None:
    print("Host's IPv6 Address is None")
    print()
else:
    i6 = extractIPv6(ipv6)
    print()
    ipv6Check(i6)
    print()
    

# The name of the vendor that has manufactured the NIC of the victim-host interface from A).
print("Host's NIC vendor is ", macInfo(mac))
print()

# IPv4 address of the main/default gateway in the victim-host LAN.
gw = conf.route.route("0.0.0.0")[2]
print("Host's Gateway is ",gw)
print()

# The name of the main/default gateway’s manufacturer.
gw_mac =getmacbyip(gw)
print("Host's Gateway MAC is ",gw_mac)
print()
gwv =macInfo(gw_mac)
print("Host's Gateway MAC vendor is ",gwv)
print()

# The number of (other) active/responsive hosts on the victim-host LAN, besides the network’s default gateway.



networkid = networkID(gw,"255.255.255.0")+"/24"
print(networkid)
pkt = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=networkid), timeout=3)[0]

print("=======================Passive Scanning!=================================")
#Passive Sniffing
clientInfo = dict()
capture=sniff(timeout=5)

for info in capture:
    print(info[1].src +"        "+ info[0].src)

print("--------------------Passive Scanning is Done!----------------------------")
print()

# Since it's dictionary overlap data will be updated 
for client in pkt:
    print(client[1].psrc + "     "+client[1].hwsrc)
    clientInfo[client[1].psrc] = client[1].hwsrc

# The number of ‘Apple’ & 'Cisco' devices among the identified active hosts from G). I) The number of ‘Cisco’ devices among the identified active hosts from G).
print()
apple = 0
cisco = 0
for k in clientInfo.items():
    print(f'IP Address : {k[0]}')
    print(f'Vendor Information : {macInfo(k[1])}')
    if 'apple' in macInfo(k[1]).lower():
        apple += 1
    if 'cisco' in macInfo(k[1]).lower():
        cisco += 1
print()
print("Apple Devices: ", apple)
print("Cisco Devices: ",cisco)
print()

# The number of devices, among the active hosts identified in G), with ports 80 and 443 open and responding.
clientIP = clientInfo.keys()
count443 = 0
count80 = 0

for k in clientIP:
    host = k
    port = [80,443]
    for dp in port:
        sp = RandShort()
        response = sr1(IP(dst = k)/TCP(sport=sp,dport=dp,flags="S"),timeout=1)
        if response is None:
            print(f"{k}:{dp} Packet is filtered")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                rst = sr(IP(dst = k)/TCP(sport=sp,dport = dp,flags='R'),timeout=1),
                print(f"{k}:{dp} is open")
                if dp == 80:
                    count80 +=1
                if dp == 443:
                    count443 +=1
            elif response.getlayer(TCP).flags == 0x14:
                print(f"{k}:{dp} is closed")
print()
print("Number of port 80 is open ", count80)
print("Number of port 443 is open", count443)
print()
