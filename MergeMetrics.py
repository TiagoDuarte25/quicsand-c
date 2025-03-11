import os
import pandas as pd

# Define base directory containing all experiment results
BASE_DIR = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs"

# Output CSV file for merged summary of all experiments
OUTPUT_FILE = os.path.join(BASE_DIR, "merged_results.csv")

def process_experiment(directory):
    """
    Process an experiment directory by merging all client CSV files and computing mean values.
    """
    csv_files = [f for f in os.listdir(directory) if f.startswith("client") and f.endswith(".csv")]
    if not csv_files:
        return None  # Skip if no CSV files found

    dfs = []
    for csv_file in csv_files:
        file_path = os.path.join(directory, csv_file)
        df = pd.read_csv(file_path)
        dfs.append(df)

    if not dfs:
        return None

    # Merge data from all clients within an experiment
    merged_df = pd.concat(dfs, ignore_index=True)

    # Compute mean for all numerical columns
    mean_values = merged_df.mean(numeric_only=True)

    # Extract experiment name from directory name
    experiment_name = os.path.basename(directory)

    # Add experiment name as a column
    mean_values["experiment"] = experiment_name

    # Save individual summary file
    summary_file = os.path.join(directory, "summary.csv")
    mean_values.to_frame().T.to_csv(summary_file, index=False)

    return mean_values


def main():
    all_results = []
    
    # Traverse directories
    for experiment in os.listdir(BASE_DIR):
        experiment_path = os.path.join(BASE_DIR, experiment)
        if os.path.isdir(experiment_path):
            result = process_experiment(experiment_path)
            if result is not None:
                all_results.append(result)

    if all_results:
        # Merge results from all experiments
        final_df = pd.DataFrame(all_results)

        # Save combined results
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"Merged results saved to {OUTPUT_FILE}")
    else:
        print("No valid experiment data found.")


if __name__ == "__main__":
    main()