import os
import sys
import time
from datetime import datetime
import socket
from icmplib import ping
import pyshark
import psutil
import pyfiglet
import random
from termcolor import colored
from colorama import Fore
from scapy.all import *


# ----- List of Fonts for Banner ----- #
fonts = ['slant', '3-d', '3x5', '5lineoblique', 'alphabet', 'banner3-D', 'isometric1', 'letters', 'alligator', 'alligator2', 'dotmatrix', 'bubble', 'bulbhead', 'digital', 'acrobatic', 'avatar', 'barbwire', 'basic', 'bell', 'bigchief', 'binary', 'block', 'calgphy2', 'caligraphy', 'catwalk', 'chunky', 'colossal', 'computer', 'cosmike', 'cyberlarge', 'doom', 'eftitalic', pyfiglet.DEFAULT_FONT]
colors = ['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']

# ----- Random font and colors selection from lists ----- #
selectedFont = random.choice(fonts)
colorBanner = random.choice(colors)
colorSlogan = random.choice(colors)

#Main Function
def main():
    try:
        os.system('cls')

        # ----- Banner Printing ----- #
        mainBanner = pyfiglet.figlet_format("NetInspector", font=selectedFont)
        print(colored(mainBanner, colorBanner))
        print(colored("  Scan . Analyze . Protect.\n", colorSlogan))
        print(Fore.LIGHTYELLOW_EX + "Version: 1.0.1\nDeveloped By: Shyam Vagadiya and Divakar Bhatia" + Fore.RESET)

        initOpr = input("\nChoose the Operation:\n\n\t1. ICMP Scan\n\t2. Port Scan\n\t3. Packet Sniffing/Analyer\n\tQ. Quit\n\nEnter Operation Number: ")
        
        if(initOpr == '1'):
            icmp_scan()
        elif(initOpr == '2'):
            port_scan()
        elif(initOpr == '3'):
            packet_analyze()
        elif(initOpr == 'Q' or initOpr == 'q'):
            confirmExit = input("\nAre you sure you want to quit? [y/N]: ")
            if(confirmExit == 'y' or confirmExit == 'Y'):
                print(Fore.LIGHTBLACK_EX + "\nThank you for using XScan Tool.")
                time.sleep(1.5)
                os.system('cls')
                return False
            else:
                os.system('cls')
                main()
        else:
            print("\n\t### Please select a valid operation ! ###")
            time.sleep(1.5)
            main()
    except:
        sys.exit(-1)

#Operational Functions

#-------------------------------------------------------------------Function Start-------------------------------------------------------------
#Function for Ping sweep operation
def icmp_scan():
    os.system('cls')
    
    selectedFont = random.choice(fonts)
    banner = pyfiglet.figlet_format("ICMP Scan", font=selectedFont)
    print(Fore.LIGHTMAGENTA_EX + banner + Fore.RESET)

    print(Fore.RED + "\nNOTE: If you want to ping multiple hosts/IPs, please make sure each host IP is separated by comma.", Fore.RESET)
    hosts = input("\nEnter IPs separated by comma: ")
    hostsList = hosts.split(',')
    invalidHosts = []
    for eachAdd in hostsList:
        if '-' in eachAdd:
            invalidHosts.append(eachAdd)
            hostsList.remove(eachAdd)
    startTime = datetime.now()
    for eachHost in hostsList:
        try:
            response = ping(eachHost, count=3) #Pinging
            if(response.is_alive):
                print(Fore.LIGHTCYAN_EX + eachHost, Fore.LIGHTWHITE_EX + "is" + Fore.LIGHTGREEN_EX + " UP." + Fore.RESET)
            else:
                print(Fore.LIGHTCYAN_EX + eachHost, Fore.LIGHTWHITE_EX + "is" + Fore.LIGHTRED_EX + " DOWN." + Fore.RESET)
        except KeyboardInterrupt:
            sys.exit(-1)
    print("-------------------------------------------")
    endTime = datetime.now() - startTime #Calculating total elapsed time
    print(Fore.GREEN + "Scan completed in ", endTime, " Seconds.\n" + Fore.RESET)
    # Displaying skipped addresses due to invalid format
    if(len(invalidHosts) != 0):
        print(Fore.LIGHTRED_EX + "Invalid Addresses!\n")
        for i in invalidHosts:
            print("-", i)
        print(Fore.RESET)
#------------------------------------------------------------------Function Over---------------------------------------------------------------

#------------------------------------------------------------------Function Start--------------------------------------------------------------
#Function to perform port scanning
def port_scan():
    os.system('cls')

    selectedFont = random.choice(fonts)
    colorMark = random.choice(colors)
    banner = pyfiglet.figlet_format("PORT SCANNER", font=selectedFont)
    print(Fore.YELLOW + banner + Fore.RESET)
    print(colored("- NetInspector v1.0.1\n", colorMark))

    # print(Fore.LIGHTGREEN_EX + "\nOPTIONS:\n-T\tTCP Scan\n-U\tUDP Scan\n-t\tTarget address\n-p\Port(s) (Comma separated)\n")
    scanType = input("\nSelect Scan Type: [TCP/UDP/ICMP]: ")
    if(scanType == "ICMP" or scanType == "icmp"):
        icmp_scan()
    else:
        # ----- Transport Layer Decision ----- #
        s_type = None
        s_stream = None
        protoType = None

        if(scanType == "TCP" or scanType == "tcp"):
            s_type = "tcp"
            s_stream = socket.SOCK_STREAM
            protoType = socket.IPPROTO_TCP
        elif(scanType == "UDP" or scanType == "udp"):
            s_type = "udp"
            s_stream = socket.SOCK_DGRAM
            protoType = socket.IPPROTO_UDP
        else:
            print("\n\n\t! PLEASE CHOOSE A VALID SCAN TYPE !")
            time.sleep(1.5)
            port_scan()

        # ----- Scan Type Selection ----- #
        hostNum = input("\n1. Scan Single host\n2. Scan a range of hosts\n\nChoose option: ")
        # ----- Single Host Scan ----- #
        if(hostNum == '1'):
            try:
                os.system('cls')
                print(Fore.CYAN + "\n" + s_type.upper() + " Single Host Scan:" +  Fore.RESET)
                targetAddr = input("\nTarget Host: ")
                targetPorts = input("Ports (comma \',\' separated): ")
                ports = targetPorts.split(",")

                print(Fore.LIGHTRED_EX + "\n\t!!! NOTE: By default, host availability checking is omitted while scanning ports. So if the host is not alive, ports are shown" + Fore.RESET + colored(" closed|filtered. !!!", "blue"))

                startTime = datetime.now()

                def scan():
                    try:
                        hostName = socket.gethostbyaddr(targetAddr)
                        print(Fore.LIGHTYELLOW_EX + "\nScanning ", targetAddr, "(", hostName[0], ") :")
                        print(Fore.LIGHTWHITE_EX + "\nPORT", "\tSTATUS", "\t\t\tSERVICE")
                        for allOne in ports:
                            s = socket.socket(socket.AF_INET,s_stream, protoType)
                            socket.setdefaulttimeout(10)
                            result = s.connect_ex((targetAddr, int(allOne)))
                            if result==0:
                                serviceName = socket.getservbyport(int(allOne))
                                print(Fore.LIGHTGREEN_EX + allOne, "\tOPEN", "\t\t\t"+serviceName)
                                s.close()
                            else :
                                print(Fore.LIGHTGREEN_EX + allOne, "\tClosed|Filtered")
                    except KeyboardInterrupt:
                        sys.exit(-1)
                    except socket.gaierror:
                        print("\n\tHostname could not be resolved. Exiting..")
                        sys.exit()
                    except socket.error:
                        print("\n\tCouldn't connect to server.")
                        sys.exit()

                scan()

                elapsedTime = datetime.now() - startTime
                print (Fore.LIGHTCYAN_EX + "\nScan completed in " , elapsedTime, "Seconds.")
                print(Fore.LIGHTRED_EX + "\nNOTE: All the ports may show \'Closed|Filtered\' Status if target host is not alive. Please run ICMP Scan to check host status.\n" + Fore.RESET)
            except ValueError:
                print(Fore.LIGHTRED_EX + "\n\tPlease enter valid value !" + Fore.RESET)
                port_scan()
            except KeyboardInterrupt:
                sys.exit(-1)
        # ----- Range Scan ----- #
        elif(hostNum == '2'):
            os.system('cls')
            
            print(Fore.CYAN + "\n" + s_type.upper() + " Range Scan:" +  Fore.RESET)
            targetAddr = input("\nTarget Network: ")
            netSplit= targetAddr.split('.')
            a = '.'
            netSplitted = netSplit[0]+a+netSplit[1]+a+netSplit[2]+a
            startingRange = int(input("Enter the starting host: "))
            endingRange = int(input("Enter the ending host: "))
            endingRange = endingRange+1
            
            targetPorts = input("Ports (comma \',\' separated): ")
            ports = targetPorts.split(",")

            print(Fore.LIGHTRED_EX + "\n\t!!! NOTE: By default, host availability checking is omitted while scanning ports. So if the host is not alive, ports are shown closed|filtered. !!!" + Fore.RESET)

            startTime = datetime.now()

            def scan(addr):
                try:
                    hostName = socket.gethostbyaddr(addr)
                    print(Fore.LIGHTYELLOW_EX + "\nScanning ", addr, "(", hostName[0], ") :")
                    print(Fore.LIGHTWHITE_EX + "\nPORT", "\tSTATUS", "\t\t\tSERVICE")
                    for allOne in ports:
                        s = socket.socket(socket.AF_INET, s_stream, protoType)
                        socket.setdefaulttimeout(10)
                        result = s.connect_ex((addr, int(allOne)))
                        if result==0:
                            serviceName = socket.getservbyport(int(allOne))
                            print(Fore.LIGHTGREEN_EX + allOne, "\tOPEN", "\t\t\t"+serviceName)
                        else :
                            print(Fore.LIGHTGREEN_EX + allOne, "\tClosed|Filtered")
                except KeyboardInterrupt:
                    sys.exit(-1)
                except socket.gaierror:
                    print("\n\tHostname could not be resolved. Exiting..")
                    sys.exit()
                except socket.error:
                    print("\n\tCouldn't connect to server.")
                    sys.exit()

            def setAddress():
                for ip in range(startingRange, endingRange):
                    addr = netSplitted + str(ip)
                    scan(addr)
            
            setAddress()

            elapsedTime = datetime.now() - startTime
            print (Fore.LIGHTCYAN_EX + "\nScan completed in " , elapsedTime, "Seconds.")
            print(Fore.LIGHTRED_EX + "\nNOTE: All the ports may show \'Closed|Filtered\' Status if target host is not alive. Please run ICMP Scan to check host status.\n" + Fore.RESET)
        else:
            print(Fore.LIGHTRED_EX + "\n\tPlease choose valid option !" + Fore.RESET)


#------------------------------------------------------------------Function Over---------------------------------------------------------------

#------------------------------------------------------------------Function Start--------------------------------------------------------------
#Function for sniffing/analyzing packets
def packet_analyze():
    os.system('cls')

    selectedFont = random.choice(fonts)
    banner = pyfiglet.figlet_format("Packet Analyzer", font=selectedFont)
    print(Fore.LIGHTMAGENTA_EX + banner + Fore.RESET)

    optInPktAnalyze = input(Fore.LIGHTCYAN_EX + "\n1. Start new packet capture\n2. Open Existing .cap/.pcap file\n3. Go to main menu" + Fore.LIGHTYELLOW_EX + "\n\nChoose Analyzer Option: " + Fore.RESET)
    recentFiles = list()
    if(optInPktAnalyze == '1'):
        # ----- Detecting and selecting Network interface to start capturing on -----
        interfaces_onHost = psutil.net_if_addrs()
        intfCount=1
        print()
        for interface in interfaces_onHost:
            print(Fore.LIGHTWHITE_EX + str(intfCount)+".", interface)
            intfCount += 1
        intfChoosen = input(Fore.LIGHTCYAN_EX + "\nSelect Interface: " + Fore.LIGHTGREEN_EX + Fore.RESET)

        if(intfChoosen not in interfaces_onHost):
            print(Fore.LIGHTRED_EX + "\n\t!!! PLEASE CHOOSE VALID NETWORK INTERFACE !!!\n" + Fore.RESET)
            time.sleep(1.5)
            packet_analyze()
        else:
            # ----- Enable Monitor Mode W--Fi Card is choosen for sniffing -----
            monitorMode = None #Setting up default value to Monitor Mode
            if(intfChoosen.find("Wi-Fi") != -1):
                monitorMode = True #Conditional change of value of Monitor Mode

            # ----- Live Capture ----- #
            try:
                liveCapType = input(Fore.GREEN + "\nDo you want only summarized packet data? [y/N]: " + Fore.RESET)
                liveCapType.lower()
                
                summary = ""
                pktCount = ""
                if(liveCapType == 'n' or liveCapType == 'no' or liveCapType == ""):
                    summary = False
                    captBanner = "Non-summarized Live Packet Capture started.."
                    
                    pktCount = int(input(Fore.LIGHTWHITE_EX + "\nTo give you the complete view of the packets number of packet captured will be limited." + Fore.LIGHTYELLOW_EX + "\nPacket Count [1-115]: " + Fore.RESET))

                    if(pktCount <= 0 or pktCount > 115):
                        print(Fore.LIGHTRED_EX + "\n\t!!! Invalid Packet Count !!!" + Fore.RESET)
                        time.sleep(2)
                        packet_analyze()
                else:
                    summary = True
                    captBanner = "Summarized Live Capture started.."
                    pktCount = int(input(Fore.LIGHTYELLOW_EX + "\nPacket Count (0 (Zero) to set no limit): " + Fore.RESET))

                    if(pktCount < 0):
                        print(Fore.LIGHTRED_EX + "\n\tInvalid Packet Count. No limit set !\n" + Fore.RESET)
                        pktCount = None
                    elif(pktCount == 0):
                        print(Fore.CYAN + "\n\tNo limit set !\n" + Fore.RESET)
                        pktCount = None
            
                # ----- Packet Filteration ----- #
                pktFil = input(Fore.GREEN + "\nDo you want to filter packets? [y/N]: " + Fore.RESET)
                pktFil.lower()
                bpfFilter = None
                if(pktFil == 'y' or pktFil == 'yes'):
                    print(Fore.GREEN + "\nApply Filters:" + Fore.RESET)
                    dataStreamFilter = input(Fore.LIGHTWHITE_EX + "Type [TCP/UDP/ICMP] (Leave blank for no preference): " +  Fore.LIGHTMAGENTA_EX)

                    bpfFilter = ""
                    if(str(dataStreamFilter).lower() == "tcp" or str(dataStreamFilter).lower() == "udp"):
                        protoFilter = input(Fore.LIGHTWHITE_EX + "Specfic Protocol (Port) to Filter out (Leave blank for no preferece): " +  Fore.LIGHTMAGENTA_EX)
                        if(protoFilter == ""):
                            # bpfFilter = None
                            bpfFilter = str(dataStreamFilter).lower()
                            print(Fore.LIGHTCYAN_EX + "\nNo filters implemented.." + Fore.RESET)
                        else:
                            bpfFilter = str(dataStreamFilter).lower() + " port " + protoFilter
                    elif(str(dataStreamFilter).lower() == "icmp"):
                        bpfFilter = (str(dataStreamFilter).lower())
                    else:
                        print(Fore.LIGHTRED_EX + "Invalid filter entered ! Redirecting to Packet Analyzer utility.." + Fore.RESET)
                        time.sleep(2)
                        packet_analyze()

                # ----- File Operation -----
                filePath = None
                outFileConfirm = input(Fore.LIGHTCYAN_EX + "\nWould you like to capture packets and save it in a file? [y\\N]: " + Fore.LIGHTGREEN_EX + Fore.RESET)
                # ----- Capturing and Storing in File ----- #
                if(outFileConfirm == 'y' or outFileConfirm == 'Y'):
                    fileName = input(Fore.LIGHTRED_EX + "\nNOTE: PLEASE DO NOT ENTER FILE NAME AND EXTENSION!" + Fore.LIGHTYELLOW_EX + "\nPlease provide file path: " + Fore.LIGHTBLUE_EX + Fore.RESET)
                    pathCorrection = fileName.replace('/', '\\')
                    dateNow = datetime.now()
                    filePath = pathCorrection + "\\" + str(dateNow.strftime("%B")) + str(dateNow.year) + "-" + str(dateNow.month) + "-" + str(dateNow.day) + ".pcap"

                    # ----- Disabling summarized capture if writing in the file is selected ----- #
                    liveCapType = 'n'

                    # ----- Creating History for File opening ----- #
                    recentFile = open("recentCapFile","a+")
                    recentFile.write(filePath)
                    recentFile.close()

            # ----- Packets Capture ----- #
                print(Fore.LIGHTMAGENTA_EX + captBanner + Fore.LIGHTWHITE_EX)
                time.sleep(1.5)
                capture = pyshark.LiveCapture(interface=intfChoosen, only_summaries=summary, bpf_filter=bpfFilter, output_file=filePath)
                srNo = 0
                size = os.get_terminal_size()
                for packet in capture.sniff_continuously(packet_count=pktCount):
                    if(summary):
                        if(filePath == None):
                            print(packet)
                        else:
                            pass
                    else:
                        if(filePath == None):
                            srNo += 1
                            print(Fore.YELLOW + "\n" + ("-"*size[0]) + "\n" + Fore.RESET + str(srNo) + Fore.YELLOW + "\n" + ("-"*size[0]) + "\n" + Fore.RESET)
                            print(packet)
                        else:
                            pass
            except AttributeError as e:
                pass #ignore packets that aren't TCP/UDP or IPv4
            except KeyboardInterrupt:
                sys.exit(-1)
            except:
                sys.exit()
            print (" ")
    elif(optInPktAnalyze == '2'):

        fileToOpen = input(Fore.LIGHTMAGENTA_EX + "\nPlease enter absolute file path: " + Fore.LIGHTWHITE_EX)
        if not os.path.isfile(fileToOpen):
            print('"{}" does not exist.'.format(fileToOpen), file=sys.stderr)   
            sys.exit(-1)
        
        showStruc = input(Fore.LIGHTBLUE_EX + "\nSummary only? [y/N]: " + Fore.LIGHTWHITE_EX)

        srNo = 0
        try:
            size = os.get_terminal_size()
            packets = rdpcap(fileToOpen)
            if(showStruc == 'y' or showStruc == 'Y'):
                try:
                    packets.summary()
                except KeyboardInterrupt:
                    sys.exit(-1)
            else:
                try:
                    for pkt in packets:
                        srNo += 1
                        print(Fore.YELLOW + "\n" + ("-"*size[0]) + "\n" + Fore.RESET + str(srNo) + Fore.YELLOW + "\n" + ("-"*size[0]) + "\n" + Fore.RESET)
                        pkt.show()
                except KeyboardInterrupt:
                    sys.exit(-1)
        except KeyboardInterrupt:
            sys.exit(-1)

    elif(optInPktAnalyze == '3'):
        main()
    else:
        print(Fore.RED + "\n\t!!! PLEASE CHOOSE VALID OPTION !!!\n" + Fore.RESET)
        time.sleep(1.5)
        packet_analyze()

#------------------------------------------------------------------Function Over---------------------------------------------------------------


#Calling Main Function to initiate the program
main()
#------------------------------------------------------------------End of Program---------------------------------------------------------------