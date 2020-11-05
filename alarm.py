#!/usr/bin/python3
from scapy.all import *
import pcapy
import argparse
import base64

incident = 1

def packetcallback(packet):
  global incident
  try:
    
    
    if packet[TCP].flags == 1:
        print("ALERT:",incident, "FIN scan detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
        incident += 1
        find(packet)
    elif packet[TCP].flags == 41:
        print("ALERT:",incident, "XMAS scan detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
        incident += 1
        find(packet)
    elif packet[TCP].flags == 0:
        print("ALERT:",incident, "NULL scan detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
        incident += 1
        find(packet)
    else: 
        find(packet)
         
        
    # if packet[TCP].dport == 143:
    #     if 'LOGIN' in payload:
    #         string = (payload.split('LOGIN')[1])
    #         username = str(string).split("gt", 1)[0]
    #         password = str(string).split("gt", 1)[1]
    #         password = password[2:]
    #         password = password[:-6]
    #         print('username: ' + username)
    #         print('password: ' + password)
    # 
    # 
    # if packet[TCP].dport == 21:
    #     if 'USER' in payload:
    #         username = (payload.split('USER')[1])
    #         username = username[:-5]
    #         print('Username: ' + username)
    #         # print('Incident #; ' + incident)
    #         # incident = incident + 1
    #     elif 'PASS' in payload:
    #         password = (payload.split('PASS')[1].strip("\\r\n"))
    #         password = password[:-5]
    #         print('Password: ' + password)
    # 
    # if packet[TCP].dport == 80:
    #     if 'Basic' in payload:
    #         string = (payload.split('Basic')[1])
    #         partition = '\\'
    #         stripped = string.split(partition, 1)[0]
    #         string = base64.b64decode(stripped)
    #         separator = ':'
    #         username = str(string).split(separator, 1)[0]
    #         username = username[2:]
    #         password = str(string).split(separator, 1)[1]
    #         password = password[:-1]
    #         print('Username: ' + username)
    #         print('Password: ' + password)
    # 
  except:
    pass

def find(packet):
    global incident
    payload = str(packet[TCP].load)
    try:
        #Nikto scan
        if 'Nikto' in payload:
            print("ALERT:",incident, "Nikto scan detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
            incident += 1
        #SMB 
        if packet[TCP].dport == 139:
             incident += 1
             print("ALERT:",incident, "SMB Protocol detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
             
        if packet[TCP].dport == 445:
             incident += 1
             print("ALERT:",incident, "SMB Protocol detected from " + packet[IP].src + " (" + str(packet[TCP].dport) + ")")
             
             
        #IMAP     
        if packet[TCP].dport == 143:
            if 'LOGIN' in payload:
                string = (payload.split('LOGIN')[1])
                username = str(string).split("gt", 1)[0]
                password = str(string).split("gt", 1)[1]
                username = username[1:]
                password = password[2:]
                password = password[:-6]
                print("ALERT#",incident,": Password and usernames sent in-the-clear (IMAP) (username: " + username + " password: " + password + ")")
                incident += 1
                
        #FTP
        if packet[TCP].dport == 21:
            if 'USER' in payload:
                username = (payload.split('USER')[1])
                username = username[:-5]
                print("ALERT#",incident,": Password and usernames sent in-the-clear (FTP) (username: " + username + ")")
                
            if 'PASS' in payload:
                password = (payload.split('PASS')[1].strip("\\r\n"))
                password = password[:-5]
                print("ALERT#",incident,": Password and usernames sent in-the-clear (FTP) (password: " + password + ")")
                incident += 1
                
        #HTTP
        if packet[TCP].dport == 80:
            if 'Basic' in payload:
                string = (payload.split('Basic')[1])
                partition = '\\'
                stripped = string.split(partition, 1)[0]
                string = base64.b64decode(stripped)
                separator = ':'
                username = str(string).split(separator, 1)[0]
                username = username[2:]
                password = str(string).split(separator, 1)[1]
                password = password[:-1]
                print("ALERT#",incident,": Usernames and passwords sent in-the-clear (HTTP) (username: " + username + " password: " + password + ")")
                incident += 1

    except:
        pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
    

      # if packet[TCP].dport == 80:
      # 
      #   print("ALERT: Is detected from: " + packet[IP].src)
      #   if packet[TCP].flags == 1:
      #     print("fin")
      #   elif packet[TCP].flags == 41:
      #     print("xmas")
      #   elif packet[TCP].flags == 0:
      #     print("null")
      # 
      # 
      # elif packet[TCP].flags == idk:
      #     print("nitko")