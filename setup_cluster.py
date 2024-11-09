from mininet.net import Mininet
from mininet.node import Controller
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.cli import CLI
import re
import json
import time
import subprocess
import csv
import matplotlib.pyplot as plt
import pandas as pd
import queue
import threading
from rich.progress import Progress
import itertools

def add_ccas(h1, h2):
    info('--- Adding CCAs to kernel\n')
    h1.cmd('sudo modprobe -a tcp_bic')
    h1.cmd('sudo modprobe -a tcp_cdg')
    h1.cmd('sudo modprobe -a tcp_dctcp')
    h1.cmd('sudo modprobe -a tcp_diag')
    h1.cmd('sudo modprobe -a tcp_highspeed')
    h1.cmd('sudo modprobe -a tcp_htcp')
    h1.cmd('sudo modprobe -a tcp_hybla')
    h1.cmd('sudo modprobe -a tcp_illinois')
    h1.cmd('sudo modprobe -a tcp_lp')
    h1.cmd('sudo modprobe -a tcp_nv')
    h1.cmd('sudo modprobe -a tcp_scalable')
    h1.cmd('sudo modprobe -a tcp_vegas')
    h1.cmd('sudo modprobe -a tcp_veno')
    h1.cmd('sudo modprobe -a tcp_westwood')
    h1.cmd('sudo modprobe -a tcp_yeah')

    h2.cmd('sudo modprobe -a tcp_bic')
    h2.cmd('sudo modprobe -a tcp_cdg')
    h2.cmd('sudo modprobe -a tcp_dctcp')
    h2.cmd('sudo modprobe -a tcp_diag')
    h2.cmd('sudo modprobe -a tcp_highspeed')
    h2.cmd('sudo modprobe -a tcp_htcp')
    h2.cmd('sudo modprobe -a tcp_hybla')
    h2.cmd('sudo modprobe -a tcp_illinois')
    h2.cmd('sudo modprobe -a tcp_lp')
    h2.cmd('sudo modprobe -a tcp_nv')
    h2.cmd('sudo modprobe -a tcp_scalable')
    h2.cmd('sudo modprobe -a tcp_vegas')
    h2.cmd('sudo modprobe -a tcp_veno')
    h2.cmd('sudo modprobe -a tcp_westwood')
    h2.cmd('sudo modprobe -a tcp_yeah')

# Enabling CCAs on the host
def enable_cca_on_host(ccas):
    info('--- Enabling CCAs on the host\n')
    for cca in ccas:
        subprocess.run(['sudo', 'modprobe', '-a', f'tcp_{cca}'])
        subprocess.run(['sudo', 'sysctl', 'net.ipv4.tcp_congestion_control='+cca])

# Helper functions
def measure_rtt(src, dst):
    result = src.cmd('ping -c 4 %s' % dst.IP())
    print(result)
    avg_rtt_search = re.search(r'rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+ ms', result)
    if avg_rtt_search:
        avg_rtt = avg_rtt_search.group(1)
        return avg_rtt
    else:
        return "RTT not found"
    

# Measure the queue occupancy using the tc command
# One could also use eBPF to gather queue stats but
# For this setup, scraping the tc command output is sufficient
def get_queue_occupancy(interface, rtt):
    result = subprocess.run(['tc', '-s', 'qdisc', 'show', 'dev', interface], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    queue_occupancy = []
    pattern = r"\s*(backlog)\s+(\d+)b\s+(\d+)p\s+(requeues)\s+(\d+)"
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if 'netem' in line:
            if 'backlog' in lines[i+2]:
                queue_info = re.search(pattern, lines[i+2])
                if queue_info:
                    packets = int(queue_info.group(3))
                    bytes_ = int(queue_info.group(2))
                    queue_occupancy.append({
                        'time': rtt,
                        'packets': packets,
                        'bytes': bytes_
                    })
                    break
    return queue_occupancy

# Read the config from the json file.
def read_config():
    with open('config.json', 'r') as f:
        data = json.load(f)
        return data

# Extract the network settings from the config
# and return them as a list.
def get_network_settings(config):
    bw = config['bw']
    rtt = config['rtt']
    queue_size = config['queue_size']

    return list(itertools.product(bw, rtt, queue_size))


# Setup the server (and the client, because why not) for iperf transfer
# by setting the cca using sysctl. If a CCA is not available, then it needs
# to be installed first.
def setup_iperf(h1, h2, cca):
    info('--- Checking enabled CCAs\n')
    client_cca = h1.cmd('cat /proc/sys/net/ipv4/tcp_available_congestion_control')
    server_cca = h2.cmd('cat /proc/sys/net/ipv4/tcp_available_congestion_control')

    info('Client CCAs: %s\n' % client_cca)
    info('Server CCAs: %s\n' % server_cca)

    cca_set = 'sudo sysctl net.ipv4.tcp_congestion_control='+cca
    info('--- Setting CCA: %s\n' % cca_set)
    set_output_client = h1.cmd(cca_set)
    set_output_server = h2.cmd(cca_set)
    h1.cmd('sysctl -p')
    h2.cmd('sysctl -p')

    print(f'Client CCA set output: {set_output_client}')
    print(f'Server CCA set output: {set_output_server}')

    info('--- Verifying CCA\n')
    client_cca = h1.cmd('cat /proc/sys/net/ipv4/tcp_congestion_control')
    server_cca = h2.cmd('cat /proc/sys/net/ipv4/tcp_congestion_control')
    print(f'Client CCA set: {client_cca}')
    print(f'Server CCA set: {server_cca}')

# Record the queue occupancy and save it to a csv file
# The saved traces will be stored in the ./results/ directory
def capture_queue_occupancy(config, total_duration, queue_data, host_number, progress_data_queue, task_id, experiment_done, file_switched, netset):
    rtt_counter = 0
    start_time = time.time()
    prev_queue_occupancy = get_queue_occupancy(f's{host_number}-eth2', rtt_counter)
    netset_counter = 0
    last_check_time = start_time
    wait_time = total_duration
    wait_time = total_duration + len(netset)
    while time.time() - start_time < wait_time:
        current_queue_occupancy = get_queue_occupancy(f's{host_number}-eth2', rtt_counter)
        rtt_counter += 1
        if len(current_queue_occupancy) != 0 and len(prev_queue_occupancy) != 0:
            if config['suppress_logs'] == "false":
                info(f'--- Current queue occupancy: {current_queue_occupancy} pkts\n')
                info(f'--- Current time: {time.time() - last_check_time} s\n')
            else:
                update_val = (time.time() - start_time) / 5
                if update_val >= total_duration/5:
                    update_val = total_duration/5
                progress_data_queue.put((task_id, update_val))
            queue_data.extend(current_queue_occupancy)
        prev_queue_occupancy = current_queue_occupancy
        try:
            time.sleep(float(netset[netset_counter][1][:-2])/1000)
            signal = experiment_done.get_nowait()
        except (Exception, queue.Empty):
            continue

        # Save queue occupancy data to CSV
        try:
            with open(f'results/queue_occupancy_{config["cca"][host_number]}_{netset[netset_counter][0]}_{netset[netset_counter][1]}_{netset[netset_counter][2]}.csv', 'w', newline='') as csvfile:
                fieldnames = ['time', 'packets', 'bytes']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in queue_data:
                    writer.writerow(entry)
        except:
            print("Error writing to file: netset_counter invalid")
        queue_data = []
        current_queue_occupancy = []
        prev_queue_occupancy = []
        last_check_time = time.time()
        netset_counter+=1
        rtt_counter = 0
        file_switched.put(True)

# Start the experiment by running iperf between the client and server
# Wait for the iperf flow to complete before exiting this thread
def start_experiment(net, config, network_settings, client, server, switches, counter, host_number, total_duration, experiment_done, file_switched):
    pids = []
    for setting in network_settings:
        print(f'--- Running experiment: {config["cca"][host_number]}-{setting[0]}bw-{setting[1]}-rtt-{setting[2]}q\n')

        total_duration = config['duration']
        rate = float(setting[0])
        specifier = 'mbit'
        if rate < 1:
            rate = rate * 1000
            specifier = 'kbit'

        link = net.linksBetween(net.get(f'h{counter}'), net.get(f's{host_number}'))[0]
        link.intf1.config(bw=setting[0], delay=setting[1], max_queue_size=setting[2])
        link.intf2.config(bw=setting[0], delay=setting[1], max_queue_size=setting[2])

        switches[host_number].cmd(f'tc class add dev s{host_number}-eth2 parent 5: classid 5:2 htb rate 100mbit')
        switches[host_number].cmd(f'tc filter add dev s{host_number}-eth2 protocol ip parent 5: prio 10 u32 match ip src 0.0.0.0/0 flowid 5:2')
        switches[host_number].cmd(f'tc filter add dev s{host_number}-eth2 protocol ip parent 5: prio 1 u32 match ip src 10.0.0.{counter+2} match ip dst 10.0.0.{counter+1} flowid 5:1')

        port = 23550 + host_number
        client.cmd(f'iperf -s -p {port} > /dev/null &')
        client_iperf_pid = client.cmd('echo $!')
        server_cmd = f"iperf -c 10.0.0.{counter+1} -p {port} -t {total_duration} > /dev/null &"
        server.cmd(server_cmd)
        server_iperf_pid = server.cmd('echo $!')
        pids.append((client_iperf_pid, server_iperf_pid))

        # Run experiment to completion
        time.sleep(total_duration)
        experiment_done.put(True)
        # Wait for queue data to be written to file
        file_switched.get()
        # Kill iperf processes
        client.cmd(f'kill -9 {pids[0][0]}')
        server.cmd(f'kill -9 {pids[0][1]}')
        
def customTopology():
    # Setup Network
    info('--- Reading config\n')
    config = read_config()
    num_hosts = len(config['cca'])

    net = Mininet(controller=Controller, link=TCLink)

    info('--- Adding controller\n')
    net.addController('c0')

    switches = []
    clients = []
    servers = []

    # Add all the switches
    for host_number in range(num_hosts):
        info('--- Adding switch\n')
        switch = net.addSwitch(f's{host_number}')
        switches.append(switch)

    nat = net.addNAT(f'nat{host_number}', connect=False, ip='10.0.0.254', inNamespace=False)
    counter = 0

    for host_number in range(num_hosts):
        switch = switches[host_number]
        info('--- Adding NAT gateway\n')
        net.addLink(nat, switch)

        info('--- Adding hosts\n')
        client = net.addHost(f'h{counter}', ip=f'10.0.0.{counter+1}', defaultRoute='via 10.0.0.254')
        server = net.addHost(f'h{counter+1}', ip=f'10.0.0.{counter+2}', defaultRoute='via 10.0.0.254')
        info('--- Creating links\n')
        net.addLink(client, switch)
        net.addLink(server, switch)

        clients.append(client)
        servers.append(server)
        counter += 2


    info('--- Starting network\n')
    net.start()

    threads = []
    exp_threads = []
    progress_bar_color = ['red', 'green', 'cyan', 'blue']
    progress_data_queue = queue.Queue()
    counter = 0
    network_settings = get_network_settings(config)
    print("Network settings: ", network_settings)

    for host_number in range(num_hosts):
        # Verify connection by pinging
        rtt = measure_rtt(clients[host_number], servers[host_number])
        info('--- Average RTT\n')
        info(rtt, "\n")

        client = clients[host_number]
        server = servers[host_number]

        # Setup DNS
        client.cmd('echo "nameserver 8.8.8.8" > /etc/resolv.conf')
        server.cmd('echo "nameserver 8.8.8.8" > /etc/resolv.conf')

        # Enable CCAs on the host
        enable_cca_on_host(config['cca'])

        # Enable access from host machine
        client.cmd('route add default gw 10.0.0.254')
        server.cmd('route add default gw 10.0.0.254')

        client.cmd('sysctl -w net.ipv4.ip_forward=1')
        server.cmd('sysctl -w net.ipv4.ip_forward=1')

        # Enable CCAs in linux kernel
        add_ccas(client, server)

        # Setup server and client
        setup_iperf(client, server, config['cca'][host_number])
        
        experiment_done = queue.Queue()
        file_switched = queue.Queue()
        exp_thread = threading.Thread(target=start_experiment, args=(net, config, network_settings, client, server, switches, counter, host_number, config['duration'], experiment_done, file_switched))
        exp_threads.append(exp_thread)
        exp_thread.start()

        # Write queue occupancy data to CSV
        queue_data = []
        total_duration = config['duration'] * len(network_settings)
        thread = threading.Thread(target=capture_queue_occupancy, args=(config, total_duration, queue_data, host_number, progress_data_queue, host_number, experiment_done, file_switched, network_settings))
        threads.append(thread)
        thread.start()
        counter += 2

    # Waiting for queue capture threads to finish
    if config['suppress_logs'] == "true":
        with Progress() as progress:
            for host_number in range(num_hosts):
                color_number = host_number % len(progress_bar_color)
                bar_label = f"[{progress_bar_color[color_number] }] {config['cca'][host_number]}"
                progress.add_task(bar_label, total=total_duration/5, visible=True)
            
            while any(thread.is_alive() for thread in threads):
                while not progress.finished and not progress_data_queue.empty():
                    queue_item = progress_data_queue.get()
                    task_id = queue_item[0]
                    update_val = queue_item[1]
                    progress.update(task_id, completed=update_val, refresh=True)    

    for thread in threads:
        thread.join()

    for exp_thread in exp_threads:
        exp_thread.join()

    info('--- Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopology()
