import yaml
import sys

def generate_topology(number_of_clients, number_of_servers, image, latency, bandwidth, topology_name, test_name):
    with open(f"/result/topology.sh", "w") as f:
        f.write(f"#!/bin/bash\n")
        f.write(f"\n")
        f.write(f"# Create quicsand servers\n")
        for i in range(1, number_of_servers + 1):
            f.write(f"gone-cli node -- docker run --rm -d --network gone_net --ip 10.1.1.{i} --name server{i} quicsand\n")
        f.write(f"\n")
        f.write(f"# Create quicsand clients\n")
        for i in range(1, number_of_clients + 1):
            server_index = i % number_of_servers + 1
            f.write(f"gone-cli node -- docker run --rm -d --network gone_net -v \"$(pwd)/{test_name}_{topology_name}:/result\" --name client{i} quicsand 10.1.1.{server_index} client{i}\n")
        f.write(f"\n")
        
        f.write(f"# Create bridges for clients\n")
        for i in range(1, number_of_clients + 1):
            f.write(f"gone-cli bridge bridge-client{i}\n")
        f.write(f"\n")

        f.write(f"# Create bridges for servers\n")
        for i in range(1, number_of_servers + 1):
            f.write(f"gone-cli bridge bridge-server{i}\n")
        f.write(f"\n")

        f.write(f"# Create routers\n")
        f.write(f"gone-cli router router-left\n")
        f.write(f"gone-cli router router-right\n")
        f.write(f"\n")

        f.write(f"# Connect clients to routers\n")
        for i in range(1, number_of_clients + 1):
            f.write(f"gone-cli connect -w {bandwidth} -n client{i} bridge-client{i}\n")
            f.write(f"gone-cli connect -w {bandwidth} -b bridge-client{i} router-left\n")
        f.write(f"\n")

        f.write(f"# Connect servers to routers\n")
        for i in range(1, number_of_servers + 1):
            f.write(f"gone-cli connect -w {bandwidth} -n server{i} bridge-server{i}\n")
            f.write(f"gone-cli connect -w {bandwidth} -b bridge-server{i} router-right\n")
        f.write(f"\n")

        f.write(f"# Connect routers\n")
        f.write(f"gone-cli connect -l {latency} -w {bandwidth} -r router-left router-right\n")
        f.write(f"\n")

        f.write(f"# Propagate routing rules\n")
        f.write(f"gone-cli propagate router-left\n")
        f.write(f"\n")

        f.write(f"# Unpause servers\n")
        for i in range(1, number_of_servers + 1):
            f.write(f"gone-cli unpause server{i}\n")
        f.write(f"\n")

        f.write(f"# Unpause all nodes\n")
        f.write(f"gone-cli unpause -a")
    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python TopologyGenerator.py <topology_name> <test_name>")
        sys.exit(1)

    topology_name = sys.argv[1].strip('"')
    test_name = sys.argv[2].strip('"')

    print(f"Generating topology {topology_name}...")

    with open("topologies.yaml", "r") as yaml_file:
        topologies = yaml.safe_load(yaml_file)

    if topology_name in topologies['topologies']:
        topology = topologies['topologies'][topology_name]
        generate_topology(
            number_of_clients=topology['number_of_clients'],
            number_of_servers=topology['number_of_servers'],
            image=topology['image'],
            latency=f"{topology['latency']}",
            bandwidth=topology['bandwidth'],
            topology_name=f"{topology_name}",
            test_name=test_name
        )
    else:
        print(f"Topology {topology_name} not found.")