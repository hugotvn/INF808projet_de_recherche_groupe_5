import json
import uuid
from datetime import datetime

def generate_id(object_type):
    return f"{object_type}--{str(uuid.uuid4())}"

def convert_wireshark_to_stix(input_file, output_file):
    with open(input_file, 'r') as f:
        data_list = json.load(f)

    observed_data = []
    identity_id = generate_id("identity")
    now = datetime.utcnow().isoformat() + "Z"

    for idx, packet in enumerate(data_list):
        layers = packet.get("_source", {}).get("layers", {})
    
        ip_src = layers.get("ip", {}).get("ip.src", "")
        ip_dst = layers.get("ip", {}).get("ip.dst", "")
        src_port = int(layers.get("tcp", {}).get("tcp.srcport", ""))
        dst_port = int(layers.get("tcp", {}).get("tcp.dstport", ""))
        protocols = []

        if "ip" in layers:
            protocols.append("ip")
        if "tcp" in layers:
            protocols.append("tcp")
        if "udp" in layers:
            protocols.append("udp")
        if "icmp" in layers:
            protocols.append("icmp")
        if "urlencoded-form" in layers:
            for i in layers["urlencoded-form"]:
                if "ldap" in i :
                    protocols.append("ldap")
                    
        observed_data.append({
            "type": "network-traffic",
            "id": generate_id("network-traffic"),
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "protocols": protocols,
            "ip_dst": ip_dst,
            "ip_src": ip_src,
            "port_src": src_port,
            "port_dst": dst_port
        })

    bundle = {
        "type": "bundle",
        "id": generate_id("bundle"),
        "spec_version": "2.0",
        "objects": [
            {
                "type": "identity",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "Wireshark STIX converter",
                "identity_class": "program"
            },
            *observed_data
        ]
    }

    with open(output_file, "w") as f:
        json.dump(bundle, f, indent=4)

# Exemple d'utilisation
convert_wireshark_to_stix("wireshark.json", "stix_output.json")
