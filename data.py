from scapy.all import *
import pandas as pd
from scapy.all import*
import socket as s
pcap="C:\\Users\\cdac-\\Downloads\\2022-02-23-traffic-analysis-exercise.pcap\\2022-02-23-traffic-analysis-exercise.pcap"
p=rdpcap(pcap)
print(p)
protocol_names = {
    1: "ICMP",
    2:"IGMP",
    41:"IPv6",
    6: "TCP",
    17: "UDP",
    80: "HTTP",
    443:"HTTPS",
    21:"FTP",
    25:"SMTP",
    110:"POP3",
    143:"IMAP",
    53:"DNS",
    22:"SSH",
    23:"Telnet",
    68:"DHCP(Client)",
    67:"DHCP(server)",
    123:"NTP"
}
d = []
cn=0
#pcap_reader = RawPcapReader(pcap)
for i in p:
    cn =cn+1

    if IP in i:
        source_ip = i[IP].src
        destination_ip = i[IP].dst
        if hasattr(i[IP], "proto"):
            pnum = i[IP].proto
        else:
            pnum = None
       
        if TCP in i:
            source_port = i[TCP].sport 
            destination_port = i[TCP].dport 
            payload = i[TCP].payload
            protocol = protocol_names.get(pnum, 'Unknown')
        elif UDP in i:
            source_port = i[UDP].sport
            destination_port = i[UDP].dport
            payload = i[UDP].payload
            protocol = protocol_names.get(pnum, 'Unknown')
        
           
        else:
            source_port=""   
            destination_port=""
            payload=i.payload
            protocol=protocol_names.get(pnum,'Unknown')

        

      
        data_length = len(i)
        packet_info=i.summary()


        d.append({'Source IP': source_ip,
                        'Destination IP': destination_ip,
                        'Source Port': source_port,
                        'Destination Port': destination_port,
                        'Protocol': protocol,
                        'Data Length': data_length,
                        'Info':packet_info})

#pcap_reader.close()
df = pd.DataFrame(d)

#print(df)

print(len(df))
print(len(p))
print(cn)

def aggregation_results(d):
    df=pd.DataFrame(d)
    results={
        'Number Of Packets':len(df),
        'Packet Shape':df.shape,
        'Source IP': df['Source IP'].nunique(),
        'Destination IP': df['Destination IP'].nunique(),
        'Unique Source Ports': df['Source Port'].nunique(),
        'Unique Destination Ports': df['Destination Port'].nunique(),
        'Protocols': df['Protocol'].value_counts().to_dict(),
        'Maximum Packet Length': df['Data Length'].max()
    }
    return results