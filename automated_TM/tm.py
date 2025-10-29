from pytm import TM, Actor, Server, Datastore, Dataflow, Boundary, Data, Classification
import os
import subprocess
import shutil
import json

# ----------------------------
# Define Threat Model
# ----------------------------
tm = TM("VehicleInfotainmentSystem")
tm.description = """
A connected vehicle infotainment system that communicates with the cloud for navigation,
media streaming, and over-the-air updates. The system also interfaces with the CAN bus
to read vehicle diagnostics.
"""
tm.isOrdered = True  # ensures stable dataflow numbering

# ----------------------------
# Boundaries
# ----------------------------
internet = Boundary("Internet")
vehicle_network = Boundary("Vehicle Internal Network")

# ----------------------------
# Actors
# ----------------------------
driver = Actor("Driver")
driver.inBoundary = internet
driver.description = "Vehicle owner interacting via the infotainment touchscreen"

cloud_service = Server("OEMCloudService")
cloud_service.inBoundary = internet
cloud_service.OS = "Linux"
cloud_service.isHardened = True
cloud_service.framework = "Node.js"
cloud_service.hasAccessControl = True
cloud_service.description = (
    "Manufacturer cloud backend providing navigation, updates, and telemetry endpoints"
)

# ----------------------------
# Components inside the vehicle
# ----------------------------
infotainment = Server("InfotainmentHeadUnit")
infotainment.inBoundary = vehicle_network
infotainment.OS = "Android Automotive"
infotainment.isHardened = False
infotainment.hasAccessControl = True
infotainment.framework = "Custom UI Framework"
infotainment.description = (
    "Central infotainment control unit running apps and connecting to the vehicle bus"
)

can_gateway = Server("CANGateway")
can_gateway.inBoundary = vehicle_network
can_gateway.isHardened = True
can_gateway.description = (
    "Gateway connecting infotainment to the vehicle CAN bus for diagnostics and limited control signals"
)

vehicle_bus = Datastore("CANBus")
vehicle_bus.inBoundary = vehicle_network
vehicle_bus.isHardened = True
vehicle_bus.storesSensitiveData = True
vehicle_bus.description = "Vehicle internal communication bus for ECUs and sensors"

# ----------------------------
# Data definitions
# ----------------------------
nav_data = Data("NavigationData", classification=Classification.RESTRICTED)
user_profile = Data("DriverProfile", classification=Classification.SENSITIVE)
firmware_pkg = Data("FirmwareUpdate", classification=Classification.SECRET)
telemetry = Data("TelemetryData", classification=Classification.SENSITIVE)

# ----------------------------
# Dataflows
# ----------------------------
flow_ui = Dataflow(driver, infotainment, "Driver uses touchscreen to access services")
flow_ui.protocol = "Bluetooth"
flow_ui.data = user_profile

flow_cloud = Dataflow(
    infotainment, cloud_service, "Infotainment syncs navigation and firmware data"
)
flow_cloud.protocol = "HTTP"
flow_cloud.data = [nav_data, firmware_pkg]

flow_update = Dataflow(
    cloud_service, infotainment, "Cloud sends firmware update to infotainment unit"
)
flow_update.protocol = "HTTPS"
flow_update.data = firmware_pkg

flow_can = Dataflow(
    infotainment, can_gateway, "Infotainment reads diagnostics via CAN gateway"
)
flow_can.protocol = "CAN"
flow_can.data = telemetry

flow_bus = Dataflow(can_gateway, vehicle_bus, "Gateway exchanges messages with CAN bus")
flow_bus.protocol = "CAN"
flow_bus.data = telemetry

# List of all flows for diagrams
flows = [flow_ui, flow_cloud, flow_update, flow_can, flow_bus]

# Elements for DFD
elements = {
    "actors": [driver],
    "servers": [cloud_service, infotainment, can_gateway],
    "datastores": [vehicle_bus],
    "boundaries": [internet, vehicle_network],
}

# ----------------------------
# DFD Generation
# ----------------------------
def generate_dfd_dot(elements, flows, out_path="dfd.dot"):
    lines = ["digraph DFD {", "  rankdir=LR;", '  node [shape=plaintext];']

    def nid(obj):
        name = getattr(obj, "name", str(obj))
        return name.replace(" ", "_").replace("/", "_")

    for a in elements.get("actors", []):
        lines.append(f'{nid(a)} [label=<<table border="0" cellborder="1" cellspacing="0"><tr><td bgcolor="lightblue"><b>Actor</b></td></tr><tr><td>{a.name}</td></tr></table>>];')
    for s in elements.get("servers", []):
        lines.append(f'{nid(s)} [label=<<table border="0" cellborder="1" cellspacing="0"><tr><td bgcolor="lightgrey"><b>Server</b></td></tr><tr><td>{s.name}<br/>{getattr(s,"OS","")}</td></tr></table>>];')
    for d in elements.get("datastores", []):
        lines.append(f'{nid(d)} [label=<<table border="0" cellborder="1" cellspacing="0"><tr><td bgcolor="lightyellow"><b>Datastore</b></td></tr><tr><td>{d.name}</td></tr></table>>];')

    for f in flows:
        src = getattr(f, "src", getattr(f, "_from", None))
        dst = getattr(f, "dst", getattr(f, "_to", None))
        src_name = getattr(src, "name", str(src))
        dst_name = getattr(dst, "name", str(dst))
        label = f"{getattr(f,'protocol','')}\\n{getattr(f,'data', '')}"
        lines.append(f"{src_name.replace(' ','_')} -> {dst_name.replace(' ','_')} [label=\"{label}\"];")

    lines.append("}")
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Wrote DFD DOT to {out_path}")

    # Try rendering to PNG
    if shutil.which("dot"):
        subprocess.run(["dot", "-Tpng", out_path, "-o", "dfd.png"], check=False)
        print("DFD rendered to dfd.png (if Graphviz installed)")

# ----------------------------
# Sequence Diagram (PlantUML)
# ----------------------------
def generate_sequence_puml(flows, out_path="sequence.puml"):
    lines = ["@startuml", "title Vehicle Infotainment Sequence"]

    participants = []
    def pname(obj):
        return getattr(obj, "name", str(obj))
    for f in flows:
        for end in [getattr(f, "src", getattr(f, "_from", None)), getattr(f, "dst", getattr(f, "_to", None))]:
            if end and pname(end) not in participants:
                participants.append(pname(end))
    for p in participants:
        lines.append(f'participant "{p}" as {p.replace(" ","_")}')

    for f in flows:
        src = getattr(f, "src", getattr(f, "_from", None))
        dst = getattr(f, "dst", getattr(f, "_to", None))
        src_id = pname(src).replace(" ","_")
        dst_id = pname(dst).replace(" ","_")
        data_name = getattr(f.data, "name", str(f.data)) if not isinstance(f.data, list) else ",".join([getattr(d, "name", str(d)) for d in f.data])
        proto = getattr(f, "protocol", "")
        label = " - ".join(filter(None, [proto, data_name]))
        lines.append(f"{src_id} -> {dst_id} : {label}")

    lines.append("@enduml")
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Wrote PlantUML sequence diagram to {out_path}")

    if shutil.which("plantuml"):
        subprocess.run(["plantuml", "-tpng", out_path], check=False)
        print("Sequence diagram rendered to PNG (if PlantUML installed)")

# ----------------------------
# Run model, generate diagrams and JSON report
# ----------------------------
if __name__ == "__main__":
    # Process threats
    tm.process()

    # Generate diagrams
    generate_dfd_dot(elements, flows)
    generate_sequence_puml(flows)

    # Generate JSON report (pretty-printed)
    json_path = "vehicle_infotiainment_report.json"
    #with open(json_path, "w") as f:
        #f.write(tm.json(indent=4))
   #print(f"JSON threat report written to {json_path}")
