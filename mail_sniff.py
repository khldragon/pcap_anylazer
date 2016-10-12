import threading
import urllib

from scapy.all import *

# our packet callback
def packet_callback(packet):

	i = 0
	while i <= 3000:

		if packet[TCP][i].payload:
	    
			mail_packet = str(packet[TCP][i].payload)

		if "wifi-mac" in mail_packet.lower():#or "latlng" in mail_packet.lower():
		    #print "[*] Server: %s" % packet[IP][0].dst
		    #print "[*] %s" % mail_packet
                    wrpcap(str(i)+".pcap",packet[TCP][i])
		    wifi_mac_left_index = mail_packet.lower().find('wifi-mac=')
	  	    wifi_pos_left_index = mail_packet.lower().find('mypos=')
		    wifi_pos_left_index1 = mail_packet.lower().find('position=')
		    if wifi_pos_left_index == -1:		
				if wifi_pos_left_index1 == -1:
						break
				else:
					wifi_pos = urllib.unquote(mail_packet[wifi_pos_left_index1+9:mail_packet.lower().find('&',wifi_pos_left_index1)])
		    else:
				wifi_pos = urllib.unquote(mail_packet[wifi_pos_left_index+6:mail_packet.lower().find('&',wifi_pos_left_index)])
	
		    #print "[*] wifi_mac_left_index: %d" % wifi_mac_left_index
		    #mail_packet[wifi_mac_left_index+9:wifi_mac_left_index+9+27]
		    wifi_mac = urllib.unquote(mail_packet[wifi_mac_left_index+9:wifi_mac_left_index+9+27])
		    
		    print "wifi-mac: %s" % wifi_mac
		    print "wifi_pos: %s" % wifi_pos
		    latlng = wifi_pos.split(',')
		    lat = latlng[0]
	   	    lng = latlng[1]
		    print "wifi_lat: %s" % lat
		    print "wifi_lng: %s" % lng
		i=i+1
            
# fire up our sniffer yes
#sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_callback,store=0)
packets = sniff(offline='meituan.pcap')
prn=packet_callback(packets)
# fire up our sniffer yes it is hahha
# fire up our sniffer yes it is hahha
