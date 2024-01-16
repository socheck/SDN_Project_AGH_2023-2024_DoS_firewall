#!/bin/python3

# imports
from random import randint as rri
import subprocess
from time import gmtime, strftime

'''Generating normal traffic between nodes who are not potential attacker'''

lov = 0 # least octet value
hov = 255 # highest octet value
dest_ip_addr_list  = [f"10.0.0.{last_octet}" for last_octet in range(1,5)]
octet = lambda: rri(lov,hov)
random_ip_address = lambda: '.'.join(str(octet()) for _ in range(4))
random_port = lambda: rri(2000,65534)

def create_query(
        layer_4_proto = "UDP",
        source_ip_addr = random_ip_address(),
        destination_ip_addr = random_ip_address(),
        source_port = random_port(),
        dest_port = random_port(),
        flag = None,
        wait_time = 0,
        size = 1500,
        count = 1000):
    command = f"sudo packit -t {layer_4_proto} -s {source_ip_addr} -d {destination_ip_addr} -S {source_port} -D {dest_port} -Z {size} -c {count} -w {wait_time} &"
    if flag:
        command += " -F S"
    return command

def create_log_file(hostname):
    file_name = f"logfile_{hostname}_{strftime('%Y-%m-%d-%H-%M-%S', gmtime())}"
    command = f"touch ./{file_name}"
    subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read()
    return file_name


#subprocess.Popen(f"{create_query()} >> logg.log" , shell=True, stdout=subprocess.PIPE).stdout.read()

