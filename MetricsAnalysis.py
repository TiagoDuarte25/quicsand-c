import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Mapping of column names to human-readable labels
LABELS = {
    'avg_rtt': 'Average RTT (ms)',
    'retransmitted_packets': 'Retransmitted Packets',
    'system_cpu_time_used': 'CPU Time Used (s)',
    'max_resident_set_size': 'Max Memory Usage (KB)',
    'latency': 'Network Latency (ms)',
    'bandwidth': 'Bandwidth (Mbps)',
    'number_of_clients': 'Number of Clients',
    'number_servers': 'Number of Servers',
    'request_size': 'Request Size (bytes)',
    'response_size': 'Response Size (bytes)',
    'file_size': 'File Size (KB)'
    'throughput': 'Throughput (Bps)'
    'resolution': 'Resolution (Kbps)'
}

# Set base directory
BASE_DIR_LOGS = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs"
BASE_DIR_GRAPHS = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/graphs"

# Define combined x metrics
combined_x_metrics = [
    ['latency', 'bandwidth'],
    ['number_of_clients', 'number_servers'],
    ['request_size', 'response_size']
]

# RR workload

RR_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "rr_metrics_summary.csv")

graph_dir = os.path.join(BASE_DIR_GRAPHS, "rr_graphs")

# Create directory for graphs if it doesn't exist
os.makedirs(graph_dir, exist_ok=True)

# Read summary file
rr_summary = pd.read_csv(RR_SUMMARY_FILE)

# Define y metrics and x metrics
y_metrics = ['avg_rtt', 'retransmitted_packets', 'system_cpu_time_used', 'max_resident_set_size']
x_metrics = ['latency', 'bandwidth', 'number_of_clients', 'number_servers', 'request_size', 'response_size']

# Generate bar plots for each combination of x and y metrics
for y_metric in y_metrics:
    for x_metric in x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation')
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
        plt.xlabel(LABELS.get(x_metric, x_metric))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}.png'))
        plt.close()

# Generate bar plots for combined x metrics
for y_metric in y_metrics:
    for x_metric_pair in combined_x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=rr_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
        plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
        plt.close()

# UP and DW workload

UP_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "up_metrics_summary.csv")
DW_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "dw_metrics_summary.csv")

up_graph_dir = os.path.join(BASE_DIR_GRAPHS, "up_graphs")
dw_graph_dir = os.path.join(BASE_DIR_GRAPHS, "dw_graphs")

# Create directory for graphs if it doesn't exist
os.makedirs(up_graph_dir, exist_ok=True)
os.makedirs(dw_graph_dir, exist_ok=True)

# Read summary file
up_summary = pd.read_csv(UP_SUMMARY_FILE)

# Define y metrics and x metrics
y_metrics = ['throughput', 'retransmitted_packets', 'system_cpu_time_used', 'max_resident_set_size']
x_metrics = ['latency', 'bandwidth', 'number_of_clients', 'number_servers', 'file_size']

# Generate bar plots for each combination of x and y metrics
for y_metric in y_metrics:
    for x_metric in x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=up_summary, x=x_metric, y=y_metric, hue='implementation')
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
        plt.xlabel(LABELS.get(x_metric, x_metric))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(up_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
        plt.close()

# Read summary file
dw_summary = pd.read_csv(DW_SUMMARY_FILE)

# Generate bar plots for each combination of x and y metrics
for y_metric in y_metrics:
    for x_metric in x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=dw_summary, x=x_metric, y=y_metric, hue='implementation')
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
        plt.xlabel(LABELS.get(x_metric, x_metric))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(dw_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
        plt.close()

# Generate bar plots for combined x metrics
for y_metric in y_metrics:
    for x_metric_pair in combined_x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=up_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
        plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(up_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
        plt.close()

# Generate bar plots for combined x metrics
for y_metric in y_metrics:
    for x_metric_pair in combined_x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=dw_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
        plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(dw_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
        plt.close()

# STRM workload

STRM_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "strm_metrics_summary.csv")

strm_graph_dir = os.path.join(BASE_DIR_GRAPHS, "strm_graphs")

# Create directory for graphs if it doesn't exist
os.makedirs(strm_graph_dir, exist_ok=True)

# Read summary file
strm_summary = pd.read_csv(STRM_SUMMARY_FILE)

# Define y metrics and x metrics
y_metrics = ['throughput', 'retransmitted_packets', 'system_cpu_time_used', 'max_resident_set_size']
x_metrics = ['latency', 'bandwidth', 'number_of_clients', 'number_servers', 'resolution']

# Generate bar plots for each combination of x and y metrics
for y_metric in y_metrics:
    for x_metric in x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=strm_summary, x=x_metric, y=y_metric, hue='implementation')
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
        plt.xlabel(LABELS.get(x_metric, x_metric))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(strm_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
        plt.close()

# Generate bar plots for combined x metrics
for y_metric in y_metrics:
    for x_metric_pair in combined_x_metrics:
        plt.figure(figsize=(12, 8))
        sns.barplot(data=strm_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
        plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
        plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
        plt.ylabel(LABELS.get(y_metric, y_metric))
        plt.legend(title='Implementation')
        plt.savefig(os.path.join(strm_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
        plt.close()

