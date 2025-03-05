import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import yaml
import sys

def generate_topology(number_of_clients, number_of_servers, middle_endpoint, image, latency, upload, download, topology_name):
    experiment = ET.Element('experiment', boot="kollaps:2.0")
    
    services = ET.SubElement(experiment, 'services')
    ET.SubElement(services, 'service', name="dashboard", image="kollaps/dashboard:1.0", supervisor="true", port="8088")

    if number_of_servers > 1:
        for i in range(1, number_of_clients + 1):
            ET.SubElement(services, 'service', name=f"client{i}", image=image, command=f"['server','{i}']")
    else:
        for i in range(1, number_of_clients + 1):
            ET.SubElement(services, 'service', name=f"client{i}", image=image, command=f"['server','1']")

    ET.SubElement(services, 'service', name="server", image=image, share="false")
    
    bridges = ET.SubElement(experiment, 'bridges')
    ET.SubElement(bridges, 'bridge', name="s1")
    
    links = ET.SubElement(experiment, 'links')
    for i in range(1, number_of_clients + 1):
        ET.SubElement(links, 'link', origin=f"client{i}", dest="s1", latency=latency, upload=upload, download=download, network="quicsand_network")
    
    ET.SubElement(links, 'link', origin="s1", dest=f"server", latency=latency, upload=upload, download=download, network="quicsand_network")
    
    dynamic = ET.SubElement(experiment, 'dynamic')
    for i in range(1, number_of_clients + 1):
        ET.SubElement(dynamic, 'schedule', name=f"client{i}", time="1.0", action="join")

    ET.SubElement(dynamic, 'schedule', name="server", time="0.0", action="join", amount=str(number_of_servers))
    
    xml_str = ET.tostring(experiment, encoding='utf-8')
    parsed_str = minidom.parseString(xml_str)
    pretty_xml_as_string = parsed_str.toprettyxml(indent="    ")
    
    with open(f"resources/topologies/{topology_name}", "w") as f:
        f.write(pretty_xml_as_string)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python TopologyGenerator.py <topology_name>")
        sys.exit(1)

    topology_name = sys.argv[1].strip('"')

    print(f"Generating topology {topology_name}...")

    with open("topologies.yaml", "r") as yaml_file:
        topologies = yaml.safe_load(yaml_file)

    if topology_name in topologies['topologies']:
        topology = topologies['topologies'][topology_name]
        generate_topology(
            number_of_clients=topology['number_of_clients'],
            number_of_servers=topology['number_of_servers'],
            middle_endpoint=topology['middle_endpoint'],
            image=topology['image'],
            latency=f"{topology['latency']}",
            upload=topology['upload'],
            download=topology['download'],
            topology_name=f"{topology_name}.xml"
        )
    else:
        print(f"Topology {topology_name} not found.")