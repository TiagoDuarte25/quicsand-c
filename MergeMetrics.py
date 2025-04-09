import os
import pandas as pd

# Define base directory containing all experiment results
BASE_DIR = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs"

def parse_file_size(size_str):
    """Convert file size from human-readable format to bytes."""
    if size_str.endswith("kb"):
        return int(size_str[:-2])
    elif size_str.endswith("mb"):
        return int(size_str[:-2]) * 1000
    elif size_str.endswith("gb"):
        return int(size_str[:-2]) * 1000000
    else:
        return int(size_str)

def parse_bitrate(bitrate):
    if bitrate.endswith("Kbps"):
        return int(bitrate[:-4])
    elif bitrate.endswith("Mbps"):
        return int(bitrate[:-4]) * 1000
    elif bitrate.endswith("Gbps"):
        return int(bitrate[:-4]) * 1000000
    else:
        return int(bitrate)

def parse_latency(latency):
    if latency == 'low':
        return 25
    elif latency == 'mid':
        return 200
    elif latency == 'high':
        return 100
    else:
        return -1

def parse_bandwidth(bandwidth):
    if bandwidth == 'low':
        return 100
    elif bandwidth == 'mid':
        return 1000
    elif bandwidth == 'high':
        return 500
    else:
        return -1

# Function to parse directory name and extract parameters
def parse_directory_name(directory_name):
    parts = directory_name.split('_')
    match parts[1]:
        case 'rr':
            return {
                'workload_type': parts[1],
                'request_size': int(parts[2]),
                'response_size': int(parts[3]) * int(parts[2]),
                'latency': parse_latency(parts[5]),
                'bandwidth': parse_bandwidth(parts[7]),
                'number_clients': int(parts[9]),
                'number_servers': int(parts[10])
            }
        case 'up':
            return {
                'workload_type': parts[1],
                'file_size': parse_file_size(parts[2]),
                'latency': 25 if parts[4] == 'low' else 200 if parts[4] == 'mid' else 100,
                'bandwidth': 100 if parts[6] == 'low' else 500 if parts[6] == 'mid' else 1000,
                'number_clients': int(parts[8]),
                'number_servers': int(parts[9])
            }
        case 'dw':
            return {
                'workload_type': parts[1],
                'file_size': parse_file_size(parts[2]),
                'latency': 25 if parts[4] == 'low' else 200 if parts[4] == 'mid' else 100,
                'bandwidth': 100 if parts[6] == 'low' else 500 if parts[6] == 'mid' else 1000,
                'number_clients': int(parts[9]),
                'number_servers': int(parts[9])
            }
        case 'strm':
            return {
                'workload_type': parts[1],
                'bitrate': parse_bitrate(parts[2]),
                'latency': 25 if parts[4] == 'low' else 200 if parts[4] == 'mid' else 100,
                'bandwidth': 100 if parts[6] == 'low' else 500 if parts[6] == 'mid' else 1000,
                'number_clients': int(parts[8]),
                'number_servers': int(parts[9])
            }

def process_experiment(base_directory, directory, implementation):
    """
    Process an experiment directory by merging all client CSV files and computing mean values.
    """
    csv_files = [f for f in os.listdir(directory) if f.startswith("client") and f.endswith(".csv")]
    if not csv_files:
        return None  # Skip if no CSV files found

    # print(f"Processing {directory}...")
    dfs = []
    for csv_file in csv_files:
        file_path = os.path.join(directory, csv_file)
        # print(f"Reading {file_path}...")
        try:
            df = pd.read_csv(file_path)
        except Exception as e:
            # print(f"Error reading file {file_path}: {e}")
            df = None
            continue 
        dfs.append(df)

    if not dfs:
        return None

    # Merge data from all clients within an experiment
    merged_df = pd.concat(dfs, ignore_index=True)

    # Compute mean for all numerical columns
    mean_values = merged_df.mean(numeric_only=True)

    # Extract experiment name from directory name
    experiment_name = os.path.basename(directory)

    params = parse_directory_name(experiment_name)
    mean_values['implementation'] = implementation
    mean_values['workload_type'] = params['workload_type']
    mean_values['latency'] = params['latency']
    mean_values['bandwidth'] = params['bandwidth']
    mean_values['number_clients'] = params['number_clients']
    mean_values['number_servers'] = params['number_servers']
    
    match params['workload_type']:
        case 'rr':
            mean_values['request_size'] = params['request_size']
            mean_values['response_size'] = params['response_size']
            summary_file = os.path.join(base_directory, "rr_metrics_summary.csv")
        case 'up':
            mean_values['file_size'] = params['file_size']
            summary_file = os.path.join(base_directory, "up_metrics_summary.csv")
        case 'dw':
            mean_values['file_size'] = params['file_size']
            summary_file = os.path.join(base_directory, "dw_metrics_summary.csv")
        case 'strm':
            mean_values['bitrate'] = params['bitrate']
            summary_file = os.path.join(base_directory, "strm_metrics_summary.csv")

    mean_values.drop(['total_bytes_sent','total_bytes_received','user_cpu_time_used','system_cpu_time_used','max_rtt','min_rtt','packet_loss','retransmitted_packets','total_sent_bytes','total_received_bytes'], inplace=True)

    # Append the mean values to the summary file
    if os.path.exists(summary_file):
        mean_values.to_frame().T.to_csv(summary_file, mode='a', header=False, index=False)
    else:
        mean_values.to_frame().T.to_csv(summary_file, index=False)


def main():
    all_results = []

    # remove old summary files
    for file in os.listdir(BASE_DIR):
        if file.endswith("summary.csv"):
            os.remove(os.path.join(BASE_DIR, file))
    
    # Traverse directories
    for implementation in os.listdir(BASE_DIR):
        if os.path.isdir(os.path.join(BASE_DIR, implementation)):
            for experiment in os.listdir(os.path.join(BASE_DIR, implementation)):
                if os.path.isdir(os.path.join(BASE_DIR, implementation, experiment)):
                    experiment_path = os.path.join(BASE_DIR, implementation, experiment)
                    if os.path.isdir(experiment_path):
                        process_experiment(BASE_DIR, experiment_path, implementation)

if __name__ == "__main__":
    main()