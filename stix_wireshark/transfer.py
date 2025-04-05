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

        object_refs = {}
        if ip_src:
            object_refs["0"] = {
                "type": "ipv4-addr",
                "value": ip_src
            }
        if ip_dst:
            object_refs["1"] = {
                "type": "ipv4-addr",
                "value": ip_dst
            }

        net_traffic = {
            "type": "network-traffic",
            "is_active": False,
            "protocols": protocols,
        }
        if ip_src:
            net_traffic["src_ref"] = "0"
        if ip_dst:
            net_traffic["dst_ref"] = "1"
        if src_port:
            net_traffic["src_port"] = src_port
        if dst_port:
            net_traffic["dst_port"] = dst_port

        object_refs["2"] = net_traffic

        observed_data.append({
            "type": "observed-data",
            "id": generate_id("observed-data"),
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "objects": object_refs
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
