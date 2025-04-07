import json
import uuid
from datetime import datetime
from dateutil import parser

def change_timestamp(tmstp):
    dt = parser.parse(tmstp)
    iso_format = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return iso_format

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
        timestamp = layers.get("frame", {}).get("frame.time_utc","")
        src_port = int(layers.get("tcp", {}).get("tcp.srcport", ""))
        dst_port = int(layers.get("tcp", {}).get("tcp.dstport", ""))
        protocols = []
        toAdd={}
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
        if "http" in layers :
            protocols.append("http")
            if "http.connection" in layers["http"] :
                toAdd["http.connection"] = layers["http"]["http.connection"]
            if "http.request.full_uri" in layers["http"] :
                toAdd["http.request.full_uri"] = layers["http"]["http.request.full_uri"]
        jison = {
            "type": "network-traffic",
            "id": generate_id("network-traffic"),
            "created_by_ref": identity_id,
            "timestamp": change_timestamp(timestamp),
            "number_observed": 1,
            "protocols": protocols,
            "dst_ip": ip_dst,
            "src_ip": ip_src,
            "src_port": src_port,
            "dst_port": dst_port
        }
        for i in toAdd :
            jison[i] = toAdd[i]
                    
        observed_data.append(jison)

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
