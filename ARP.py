import scapy.all as scapy
import socket, uuid, re

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
    print(f"\n\nScanning completed. Found {len(scan_result)} responses. \n ")
    print(title)
    print (40 * "-" + "\n")
    for client in scan_result:
        print(client["ip"] + "\t\t" + client["mac"])
    print ("\n"+ 40 * "-")

scan_with_notification("1.0.0.0/8") #! Sets ip as the string 1.1.1.0/8 will scan all ips from 1.0.0.0 till 1.255.255.255


print ("My MAC address in formatted way is : ", end="")
print (':'.join(re.findall('..', '%012x' % uuid.getnode())))
hostname = socket.gethostname()
myip =  socket.gethostbyname(hostname)
print("\n"+"My IP address is: ", myip + "\n") #! Prints the IP of the machine running the script