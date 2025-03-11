import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set base directory
BASE_DIR = "/home/tiagoduarte25/Desktop/thesis/quicsand-c/resources/logs"
MERGED_FILE = os.path.join(BASE_DIR, "merged_results.csv")

# Load dataset
df = pd.read_csv(MERGED_FILE)

# Set seaborn style for better visualization
sns.set_style("whitegrid")

# 1. **RTT Distribution per Experiment (Boxplot)**
plt.figure(figsize=(12, 6))
sns.boxplot(x="experiment", y="rtt", data=df)
plt.xticks(rotation=45, ha="right")
plt.title("RTT Distribution per Experiment")
plt.xlabel("Experiment")
plt.ylabel("RTT (ms)")
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "rtt_distribution.png"))
plt.show()

# 2. **Total Bytes Sent vs. Received (Scatter Plot)**
plt.figure(figsize=(8, 5))
sns.scatterplot(x="total_bytes_sent", y="total_bytes_received", data=df, hue="experiment", palette="coolwarm", s=100)
plt.title("Total Bytes Sent vs. Received")
plt.xlabel("Total Bytes Sent")
plt.ylabel("Total Bytes Received")
plt.legend(loc="upper left", bbox_to_anchor=(1, 1))
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "bytes_sent_vs_received.png"))
plt.show()

# 3. **CPU Time Used vs. Packet Loss (Scatter Plot)**
plt.figure(figsize=(8, 5))
sns.scatterplot(x="cpu_time_used", y="packet_loss", data=df, hue="experiment", palette="viridis", s=100)
plt.title("CPU Time Used vs. Packet Loss")
plt.xlabel("CPU Time Used (s)")
plt.ylabel("Packet Loss (%)")
plt.legend(loc="upper right", bbox_to_anchor=(1, 1))
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "cpu_vs_packet_loss.png"))
plt.show()

# 4. **Average RTT vs. Experiment (Bar Plot)**
plt.figure(figsize=(10, 5))
sns.barplot(x="experiment", y="avg_rtt", data=df, palette="muted")
plt.xticks(rotation=45, ha="right")
plt.title("Average RTT per Experiment")
plt.xlabel("Experiment")
plt.ylabel("Average RTT (ms)")
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "avg_rtt_barplot.png"))
plt.show()

# 5. **Retransmitted Packets per Experiment (Bar Plot)**
plt.figure(figsize=(10, 5))
sns.barplot(x="experiment", y="retransmitted_packets", data=df, palette="pastel")
plt.xticks(rotation=45, ha="right")
plt.title("Retransmitted Packets per Experiment")
plt.xlabel("Experiment")
plt.ylabel("Retransmitted Packets")
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "retransmitted_packets.png"))
plt.show()

print("Plots saved in:", BASE_DIR)