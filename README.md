# SneakyScanner


 ![image](https://user-images.githubusercontent.com/79100627/202887416-60e5e29d-719e-434f-a65b-0895d873c653.png)
 
 Sneaky Network Scanner with Python Made by **Jay Jae Young Chung**


## Installation Requirement 

- Python
- Scapy 

## Installation Code

```pip install Scapy```

## Functionalities

- The current globally routable IPv4 address of the victim-host.
- The MAC address associated with (i.e., assigned to) the victim-host interface from A).
- The IPv6 address assigned to victim-host interface from A) – if available + EUI64 checking (Stateful or Stateless)
- The name of the vendor that has manufactured the NIC of the victim-host interface from A).
- IPv4 address of the main/default gateway in the victim-host LAN.
- The name of the main/default gateway’s manufacturer.
- The number of (other) active/responsive & Passive hosts on the victim-host LAN, besides the network’s default gateway.
- The number of ‘Apple’ devices among the identified active hosts from G).
- The number of ‘Cisco’ devices among the identified active hosts from G).
- The number of devices, among the active hosts identified in G), with ports 80 and 443 open and responding.

## Before Running Script 

Please note that subnetmask is setted with **'/24'**

Passive Scanning will be 5 seconds (You can modify if you want) 

