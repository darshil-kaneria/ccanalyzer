## Cluster Setup
1. Install Mininet:
```bash
sudo apt-get update
sudo apt-get install mininet
```

2. Update the `config.json` file with the desired settings for bandwidth, rtt delay, and the CCAs to use.
```json
{
   "bw": [5, 10],
   "rtt": ["42ms", "65ms"],
   "queue_size": [64, 128],
   "cca": ["cubic", "reno", "bbr"],
   "duration": 60,
   "suppress_logs": "true"
}
```
Given above is an example config file for running iperf flows with a combination of various network settings.

## Running experiments
1. Run the `setup_cluster.py` script with sudo:
```bash
make all
```
This will setup a cluster of nodes with two hosts and one switch, and run experiments according to the specified network settings. The results will be stored in the `results` directory as csv files.

2. Plot graphs (utility function)
```bash
python3 queue_plot.py --file <filename>
```
This should plot a graph using the queue occupancy data from the csv file. The graphs visually represent the congestion control algorithm being tested depending on the network settings used.
