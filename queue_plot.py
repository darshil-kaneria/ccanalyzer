import matplotlib.pyplot as plt
import json
import argparse
import pandas as pd

def plot_queue_occupancy(queue_occupancy, config, netset):
    netset[3] = netset[3].split('.')[0]
    x = queue_occupancy.iloc[:, [0]]
    y = queue_occupancy.iloc[:, [1]] / float(netset[3])
    plt.figure(figsize=(10, 6))
    plt.plot(x, y, linestyle='-', color='orange')
    plt.xlabel(f"Time (no. rtt)", fontsize=14)
    plt.ylabel('Packets/QueueSize', fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.ylim(0, 1)
    plt.title(f"{netset[0]} Time vs Packets ({netset[1]}bw-{netset[2]}-owd-{netset[3]}q)", fontsize=14)
    plt.grid(True)
    plt.show()

def read_config():
    with open('config.json', 'r') as f:
        data = json.load(f)
        return data
    
def parse_args():
    parser = argparse.ArgumentParser(description='Queue Monitor')
    parser.add_argument('--file', type=str, help='Input file path')
    args = parser.parse_args()
    return args

def read_queue_occupancy(file_path):
        data = pd.read_csv(file_path, header=0)
        return data

def main():
    config = read_config()
    args = parse_args()
    
    netset = args.file.split('_')[2:]
    queue_occupancy = read_queue_occupancy(args.file)
    plot_queue_occupancy(queue_occupancy, config, netset)

if __name__ == "__main__":
    main()
