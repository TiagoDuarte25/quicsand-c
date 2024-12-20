import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

def generate_topology(number_of_clients, multiple_servers, middle_endpoint, image, latency, upload, download, topology_name):
    experiment = ET.Element('experiment', boot="kollaps:2.0")
    
    services = ET.SubElement(experiment, 'services')
    ET.SubElement(services, 'service', name="dashboard", image="kollaps/dashboard:1.0", supervisor="true", port="8088")


    if multiple_servers:
        for i in range(1, number_of_clients + 1):
            ET.SubElement(services, 'service', name=f"client{i}", image=image, command=f"['server','{i}']")
    else:
        for i in range(1, number_of_clients + 1):
            ET.SubElement(services, 'service', name=f"client{i}", image=image, command="['server','1']")
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
    if multiple_servers:
        ET.SubElement(dynamic, 'schedule', name="server", time="0.0", action="join", amount=str(number_of_clients))
    else:
        ET.SubElement(dynamic, 'schedule', name="server", time="0.0", action="join", amount="1")
    
    xml_str = ET.tostring(experiment, encoding='utf-8')
    parsed_str = minidom.parseString(xml_str)
    pretty_xml_as_string = parsed_str.toprettyxml(indent="    ")
    
    with open(topology_name, "w") as f:
        f.write(pretty_xml_as_string)

if __name__ == "__main__":
    generate_topology(
        number_of_clients=10,
        multiple_servers=False,
        middle_endpoint=True,
        image="quicsand",
        latency="10",
        upload="500Mbps",
        download="500Mbps",
        topology_name="low_latency.xml"
    )