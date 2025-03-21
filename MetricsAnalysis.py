import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Mapping of column names to human-readable labels
LABELS = {
    'rtt': 'Average RTT (ms)',
    'retransmitted_packets': 'Retransmitted Packets',
    'system_cpu_time_used': 'CPU Time Used (s)',
    'max_resident_set_size': 'Max Memory Usage (KB)',
    'latency': 'Network Latency (ms)',
    'bandwidth': 'Bandwidth (Mbps)',
    'number_of_clients': 'Number of Clients',
    'number_servers': 'Number of Servers',
    'request_size': 'Request Size (bytes)',
    'response_size': 'Response Size (bytes)',
    'file_size': 'File Size (KB)',
    'throughput': 'Throughput (Bps)',
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
y_metrics = ['rtt', 'cpu_time_used', 'max_resident_set_size']
x_metrics = ['latency', 'bandwidth', 'number_clients', 'number_servers', 'request_size', 'response_size']

# Generate plots
for y_metric in y_metrics:
    for x_metric in x_metrics:
        grouped_vars = [var for var in x_metrics if var != x_metric]

        # Group by other variables
        grouped_data = rr_summary.groupby(grouped_vars)

        for group_values, group_df in grouped_data:
            plt.figure(figsize=(12, 8))

            # Ensure group_values is a tuple (for single-variable cases)
            if not isinstance(group_values, tuple):
                group_values = (group_values,)

            # Generate a meaningful title and filename
            group_label = ', '.join([f'{var}={val}' for var, val in zip(grouped_vars, group_values)])
            file_label = "_".join([f"{var}_{val}" for var, val in zip(grouped_vars, group_values)]).replace(" ", "")

            # Plot data
            sns.barplot(data=group_df, x=x_metric, y=y_metric, hue='implementation')
            plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} | {group_label}')
            plt.xlabel(LABELS.get(x_metric, x_metric))
            plt.ylabel(LABELS.get(y_metric, y_metric))
            plt.legend(title='Implementation')

            # Save plot
            plt.savefig(os.path.join(graph_dir, f"{y_metric}_vs_{x_metric}_{file_label}.png"))
            plt.close()

# ########################### ANOTHER GRAPHICS ####################################


# unique_implementations = rr_summary['implementation'].nunique()
# markers = ["o", "s", "D", "^", "v", "P", "*"][:unique_implementations]  # Adjust marker list length
# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.lmplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation', markers=markers, height=6, aspect=1.5)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} (with Regression)')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_regression.png'))
#         plt.close()

# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.boxplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} Distribution by {LABELS.get(x_metric, x_metric)}')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_boxplot.png'))
#         plt.close()

# # Compute correlation matrix for numerical columns only
# correlation_matrix = rr_summary.corr(numeric_only=True)

# # Plot the correlation matrix
# plt.figure(figsize=(12, 8))
# sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.2f')
# plt.title('Correlation Matrix of Metrics')
# plt.savefig(os.path.join(graph_dir, 'correlation_matrix.png'))
# plt.close()


# sns.pairplot(rr_summary, vars=y_metrics + x_metrics, hue='implementation', height=2.5)
# plt.savefig(os.path.join(graph_dir, 'pairplot.png'))
# plt.close()

# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.violinplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation', split=True)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} Distribution by {LABELS.get(x_metric, x_metric)}')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_violinplot.png'))
#         plt.close()

# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         g = sns.FacetGrid(rr_summary, col="implementation", height=4, aspect=1.2)
#         g.map(sns.scatterplot, x_metric, y_metric)
#         g.set_axis_labels(LABELS.get(x_metric, x_metric), LABELS.get(y_metric, y_metric))
#         g.fig.subplots_adjust(top=0.9)
#         g.fig.suptitle(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} by Implementation')
#         g.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_facetgrid.png'))
#         plt.close()

# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.lineplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation', marker='o')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} (Line Plot)')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_lineplot.png'))
#         plt.close()

# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.swarmplot(data=rr_summary, x=x_metric, y=y_metric, hue='implementation')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)} (Swarm Plot)')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric}_swarmplot.png'))
#         plt.close()

# #################################################################################

# # Generate bar plots for combined x metrics
# for y_metric in y_metrics:
#     for x_metric_pair in combined_x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=rr_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
#         plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
#         plt.close()

# # UP and DW workload

# UP_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "up_metrics_summary.csv")
# DW_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "dw_metrics_summary.csv")

# up_graph_dir = os.path.join(BASE_DIR_GRAPHS, "up_graphs")
# dw_graph_dir = os.path.join(BASE_DIR_GRAPHS, "dw_graphs")

# # Create directory for graphs if it doesn't exist
# os.makedirs(up_graph_dir, exist_ok=True)
# os.makedirs(dw_graph_dir, exist_ok=True)

# # Define combined x metrics
# combined_x_metrics = [
#     ['latency', 'bandwidth'],
#     ['number_of_clients', 'number_servers']
# ]

# # Read summary file
# up_summary = pd.read_csv(UP_SUMMARY_FILE)
# up_summary.columns = up_summary.columns.str.strip()

# # Define y metrics and x metrics
# y_metrics = ['throughput', 'retransmitted_packets', 'system_cpu_time_used', 'max_resident_set_size']
# x_metrics = ['latency', 'bandwidth', 'number_of_clients', 'number_servers', 'file_size']

# # Generate bar plots for each combination of x and y metrics
# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=up_summary, x=x_metric, y=y_metric, hue='implementation')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(up_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
#         plt.close()

# # Read summary file
# dw_summary = pd.read_csv(DW_SUMMARY_FILE)
# dw_summary.columns = up_summary.columns.str.strip()

# # Generate bar plots for each combination of x and y metrics
# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=dw_summary, x=x_metric, y=y_metric, hue='implementation')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(dw_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
#         plt.close()

# # Generate bar plots for combined x metrics
# for y_metric in y_metrics:
#     for x_metric_pair in combined_x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=up_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
#         plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(up_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
#         plt.close()

# # Generate bar plots for combined x metrics
# for y_metric in y_metrics:
#     for x_metric_pair in combined_x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=dw_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
#         plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(dw_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
#         plt.close()

# # STRM workload

# STRM_SUMMARY_FILE = os.path.join(BASE_DIR_LOGS, "strm_metrics_summary.csv")

# strm_graph_dir = os.path.join(BASE_DIR_GRAPHS, "strm_graphs")

# # Create directory for graphs if it doesn't exist
# os.makedirs(strm_graph_dir, exist_ok=True)

# # Read summary file
# strm_summary = pd.read_csv(STRM_SUMMARY_FILE)

# # Define y metrics and x metrics
# y_metrics = ['throughput', 'retransmitted_packets', 'system_cpu_time_used', 'max_resident_set_size']
# x_metrics = ['latency', 'bandwidth', 'number_of_clients', 'number_servers', 'resolution']

# # Generate bar plots for each combination of x and y metrics
# for y_metric in y_metrics:
#     for x_metric in x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=strm_summary, x=x_metric, y=y_metric, hue='implementation')
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric, x_metric)}')
#         plt.xlabel(LABELS.get(x_metric, x_metric))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(strm_graph_dir, f'{y_metric}_vs_{x_metric}.png'))
#         plt.close()

# # Generate bar plots for combined x metrics
# for y_metric in y_metrics:
#     for x_metric_pair in combined_x_metrics:
#         plt.figure(figsize=(12, 8))
#         sns.barplot(data=strm_summary, x=x_metric_pair[0], y=y_metric, hue='implementation', dodge=True)
#         plt.title(f'{LABELS.get(y_metric, y_metric)} vs {LABELS.get(x_metric_pair[0], x_metric_pair[0])} and {LABELS.get(x_metric_pair[1], x_metric_pair[1])}')
#         plt.xlabel(LABELS.get(x_metric_pair[0], x_metric_pair[0]))
#         plt.ylabel(LABELS.get(y_metric, y_metric))
#         plt.legend(title='Implementation')
#         plt.savefig(os.path.join(strm_graph_dir, f'{y_metric}_vs_{x_metric_pair[0]}_{x_metric_pair[1]}.png'))
#         plt.close()

