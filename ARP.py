import scapy.all as scapy

title = "IP\t\t\tMAC Address"

def scan(ip):
    #! Creates the ARP request and broadcasts it to the open MAC of ff:ff:ff:ff:ff:ff
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #! Makes the ARP and broadcast one packet
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    #! For each answered packet, we get the MAC and IP of the device
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list  

   
#! Makes  the scan and prints the result and progress
def scan_with_notification(ip):
    print(ip)
    print(f"Scanning {ip}...")
    scan_result = scan(ip)
    print(f"\n +\n + Scanning completed. Found {len(scan_result)} responses.")
    print(title)
    print ("IP\t\t\tMAC Address")
    for client in scan_result:
        print(client["ip"] + "\t\t" + client["mac"])

scan_with_notification("10.255.196.0/24") #! Sets ip as the string 1.1.1.0/8 will scan all ips from 1.0.0.0 till 1.255.255.255





