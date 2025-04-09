import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Mapping of column names to human-readable labels
LABELS = {
    'rtt': 'Average RTT (ms)',
    'retransmitted_packets': 'Retransmitted Packets',
    'max_resident_set_size': 'Max Memory Usage (KB)',
    'latency': 'Network Latency (ms)',
    'bandwidth': 'Bandwidth (Mbps)',
    'number_clients': 'Number of Clients',
    'number_servers': 'Number of Servers',
    'request_size': 'Request Size (bytes)',
    'response_size': 'Response Size (bytes)',
    'file_size': 'File Size (KB)',
    'throughput': 'Throughput (Bps)',
    'bitrate': 'Bitrate (Kbps)',
    'app_throughput': 'Applicational Throughput (Bps)',
    'cpu_time_used': 'CPU Time Used (s)',
    'avg_rtt': 'Average RTT (ms)'
}

# Set base directory
BASE_DIR_LOGS = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs"
BASE_DIR_GRAPHS = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/graphs/msquic_graphs"

# Set global font sizes for better readability in LaTeX papers
plt.rcParams.update({
    'font.size': 10,  # General font size
    'axes.titlesize': 16,  # Title font size
    'axes.labelsize': 12,  # Axis label font size
    'xtick.labelsize': 10,  # X-axis tick label font size
    'ytick.labelsize': 10,  # Y-axis tick label font size
    'legend.fontsize': 10,  # Increased legend font size for better readability
    'figure.titlesize': 12  # Figure title font size
})

# remove old graphs
os.system(f"rm -rf {BASE_DIR_GRAPHS}/*")

os.makedirs(BASE_DIR_GRAPHS, exist_ok=True)

# RR workload

RR_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "rr_metrics_summary.csv")

graph_dir = os.path.join(BASE_DIR_GRAPHS, "rr_graphs")

# Create directory for graphs if it doesn't exist
os.makedirs(graph_dir, exist_ok=True)

# Read summary file
rr_summary = pd.read_csv(RR_SUMMARY_FILE)

# Define y metrics and x metrics
y_metrics = ['avg_rtt', 'cpu_time_used', 'max_resident_set_size']
x_metrics = ['latency', 'bandwidth', 'number_clients', 'number_servers', 'request_size', 'response_size']

msquic_rr_summary = rr_summary[rr_summary['implementation'] == 'msquic']

# Generate plots
for y_metric in y_metrics:
    for x_metric in x_metrics:
        grouped_vars = [var for var in x_metrics if var != x_metric]

        # Create a directory for the current y_metric
        y_metric_dir = os.path.join(graph_dir, y_metric)
        os.makedirs(y_metric_dir, exist_ok=True)

        # Group by other variables
        grouped_data = msquic_rr_summary.groupby(grouped_vars)

        for group_values, group_df in grouped_data:
            plt.figure(figsize=(7, 5))

            # Ensure group_values is a tuple (for single-variable cases)
            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            # Generate a meaningful title and filename
            group_label = ', '.join([f'{var}={val}' for var, val in zip(grouped_vars, group_values)])
            file_label = "_".join([f"{var}_{val}" for var, val in zip(grouped_vars, group_values)]).replace(" ", "")

            # Create a subdirectory for the current x_metric within the y_metric directory
            x_metric_dir = os.path.join(y_metric_dir, x_metric)
            os.makedirs(x_metric_dir, exist_ok=True)

            # Plot data
            sns.barplot(data=group_df, x=x_metric, y=y_metric, hue='implementation')
            # plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} | {group_label}')
            plt.xlabel(LABELS.get(x_metric, x_metric))
            plt.ylabel(LABELS.get(y_metric, y_metric))
            plt.legend(title='Implementation')

            # Save plot
            plt.savefig(os.path.join(x_metric_dir, f"{file_label}.png"))
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
up_summary.columns = up_summary.columns.str.strip()

msquic_up_summary = up_summary[up_summary['implementation'] == 'msquic']

# Define y metrics and x metrics
y_metrics = ['throughput', 'cpu_time_used', 'max_resident_set_size', 'app_throughput', 'avg_rtt']
x_metrics = ['latency', 'bandwidth', 'number_clients', 'number_servers', 'file_size']

# Generate plots
for y_metric in y_metrics:
    for x_metric in x_metrics:
        grouped_vars = [var for var in x_metrics if var != x_metric]

        # Create a directory for the current y_metric
        y_metric_dir = os.path.join(up_graph_dir, y_metric)
        os.makedirs(y_metric_dir, exist_ok=True)

        # Group by other variables
        grouped_data = msquic_up_summary.groupby(grouped_vars)

        for group_values, group_df in grouped_data:
            plt.figure(figsize=(7, 5))

            # Ensure group_values is a tuple (for single-variable cases)
            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            # Generate a meaningful title and filename
            group_label = ', '.join([f'{var}={val}' for var, val in zip(grouped_vars, group_values)])
            file_label = "_".join([f"{var}_{val}" for var, val in zip(grouped_vars, group_values)]).replace(" ", "")

            # Create a subdirectory for the current x_metric within the y_metric directory
            x_metric_dir = os.path.join(y_metric_dir, x_metric)
            os.makedirs(x_metric_dir, exist_ok=True)

            # Plot data
            sns.barplot(data=group_df, x=x_metric, y=y_metric, hue='implementation')
            # plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} | {group_label}')
            plt.xlabel(LABELS.get(x_metric, x_metric))
            plt.ylabel(LABELS.get(y_metric, y_metric))
            plt.legend(title='Implementation')

            # Save plot
            plt.savefig(os.path.join(x_metric_dir, f"{file_label}.png"))
            plt.close()

# Read summary file
dw_summary = pd.read_csv(DW_SUMMARY_FILE)
dw_summary.columns = dw_summary.columns.str.strip()

msquic_dw_summary = dw_summary[dw_summary['implementation'] == 'msquic']

# Generate plots
for y_metric in y_metrics:
    for x_metric in x_metrics:
        grouped_vars = [var for var in x_metrics if var != x_metric]

        # Create a directory for the current y_metric
        y_metric_dir = os.path.join(dw_graph_dir, y_metric)
        os.makedirs(y_metric_dir, exist_ok=True)

        # Group by other variables
        grouped_data = msquic_dw_summary.groupby(grouped_vars)

        for group_values, group_df in grouped_data:
            plt.figure(figsize=(7, 5))

            # Ensure group_values is a tuple (for single-variable cases)
            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            # Generate a meaningful title and filename
            group_label = ', '.join([f'{var}={val}' for var, val in zip(grouped_vars, group_values)])
            file_label = "_".join([f"{var}_{val}" for var, val in zip(grouped_vars, group_values)]).replace(" ", "")

            # Create a subdirectory for the current x_metric within the y_metric directory
            x_metric_dir = os.path.join(y_metric_dir, x_metric)
            os.makedirs(x_metric_dir, exist_ok=True)

            # Plot data
            sns.barplot(data=group_df, x=x_metric, y=y_metric, hue='implementation')
            # plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} | {group_label}')
            plt.xlabel(LABELS.get(x_metric, x_metric))
            plt.ylabel(LABELS.get(y_metric, y_metric))
            plt.legend(title='Implementation')

            # Save plot
            plt.savefig(os.path.join(x_metric_dir, f"{file_label}.png"))
            plt.close()

# STRM workload

STRM_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "strm_metrics_summary.csv")

strm_graph_dir = os.path.join(BASE_DIR_GRAPHS, "strm_graphs")

# Create directory for graphs if it doesn't exist
os.makedirs(strm_graph_dir, exist_ok=True)

# Read summary file
strm_summary = pd.read_csv(STRM_SUMMARY_FILE)
strm_summary.columns = strm_summary.columns.str.strip()

msquic_strm_summary = strm_summary[strm_summary['implementation'] == 'msquic']

# Define y metrics and x metrics
y_metrics = ['throughput', 'app_throughput', 'cpu_time_used', 'max_resident_set_size', 'avg_rtt']
x_metrics = ['latency', 'bandwidth', 'number_clients', 'number_servers', 'bitrate']

# Generate plots
for y_metric in y_metrics:
    for x_metric in x_metrics:
        grouped_vars = [var for var in x_metrics if var != x_metric]

        # Create a directory for the current y_metric
        y_metric_dir = os.path.join(strm_graph_dir, y_metric)
        os.makedirs(y_metric_dir, exist_ok=True)

        # Group by other variables
        grouped_data = msquic_strm_summary.groupby(grouped_vars)

        for group_values, group_df in grouped_data:
            plt.figure(figsize=(7, 5))

            # Ensure group_values is a tuple (for single-variable cases)
            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            # Generate a meaningful title and filename
            group_label = ', '.join([f'{var}={val}' for var, val in zip(grouped_vars, group_values)])
            file_label = "_".join([f"{var}_{val}" for var, val in zip(grouped_vars, group_values)]).replace(" ", "")

            # Create a subdirectory for the current x_metric within the y_metric directory
            x_metric_dir = os.path.join(y_metric_dir, x_metric)
            os.makedirs(x_metric_dir, exist_ok=True)

            # Plot data
            sns.barplot(data=group_df, x=x_metric, y=y_metric, hue='implementation')
            # plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} | {group_label}')
            plt.xlabel(LABELS.get(x_metric, x_metric))
            plt.ylabel(LABELS.get(y_metric, y_metric))
            plt.legend(title='Implementation')

            # Save plot
            plt.savefig(os.path.join(x_metric_dir, f"{file_label}.png"))
            plt.close()


