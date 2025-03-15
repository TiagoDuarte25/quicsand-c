import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# Function to parse directory name and extract parameters
def parse_directory_name(directory_name):
    parts = directory_name.split('_')
    return {
        'workload_type': parts[1],
        'request_size': int(parts[2]),
        'response_size': int(parts[3]) * int(parts[2]),
        'latency': 50 if parts[5] == 'low' else 200 if parts[5] == 'mid' else 400,
        'bandwidth': 100 if parts[7] == 'low' else 500 if parts[7] == 'mid' else 1000,
        'number_of_clients': int(parts[8]),
        'number_servers': int(parts[9])
    }

# Load the CSV file
file_path = '/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs/msquic/aa_rr_10_100_aa_low_lat_mid_bw_1_1/client1.csv'
df = pd.read_csv(file_path)

# Parse the directory name to get parameters
directory_name = os.path.basename(os.path.dirname(file_path))
params = parse_directory_name(directory_name)

# Add new columns
df['workload_type'] = params['workload_type']
df['request_size'] = params['request_size']
df['response_size'] = params['response_size']
df['latency'] = params['latency']
df['bandwidth'] = params['bandwidth']
df['param1'] = params['param1']
df['param2'] = params['param2']

# List of columns to plot against 'rtt'
columns_to_plot = ['total_bytes_sent', 'total_bytes_received', 'cpu_time_used', 'user_cpu_time_used', 'system_cpu_time_used', 'max_resident_set_size', 'avg_rtt', 'max_rtt', 'min_rtt', 'packet_loss', 'retransmitted_packets', 'total_sent_bytes', 'total_received_bytes', 'request_size', 'response_size', 'latency', 'bandwidth']

# Generate scatter plots for each column against 'rtt'
for column in columns_to_plot:
    plt.figure(figsize=(10, 6))
    sns.scatterplot(x=df[column], y=df['rtt'])
    plt.title(f'RTT vs {column}')
    plt.xlabel(column)
    plt.ylabel('RTT')
    plt.show()

# Generate pairplot to visualize relationships
sns.pairplot(df, vars=['rtt'] + columns_to_plot)
plt.show()