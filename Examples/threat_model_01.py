#!/usr/bin/env python3

from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, ExternalEntity

# Create a new threat model
tm = TM("Vehicle Infotainment System")
tm.description = "Threat model for a modern vehicle infotainment system"
tm.isOrdered = True
tm.mergeResponses = True

# Define trust boundaries
internet_boundary = Boundary("Internet")
vehicle_network_boundary = Boundary("Vehicle Network")
infotainment_boundary = Boundary("Infotainment System")

# External Entities
user = Actor("Driver/Passenger")
user.inBoundary = infotainment_boundary
user.levels = [2]
user.authenticatesDestination = False

mobile_device = ExternalEntity("Mobile Device")
mobile_device.inBoundary = internet_boundary
mobile_device.levels = [2]

cloud_services = ExternalEntity("Cloud Services")
cloud_services.inBoundary = internet_boundary
cloud_services.levels = [1]
cloud_services.authenticatesDestination = True

gps_satellite = ExternalEntity("GPS Satellite")
gps_satellite.inBoundary = internet_boundary
gps_satellite.levels = [1]

# Vehicle Network Components
can_bus = Server("CAN Bus")
can_bus.inBoundary = vehicle_network_boundary
can_bus.OS = "Embedded"
can_bus.isHardened = True
can_bus.onAWS = False
can_bus.levels = [1]

ecu_engine = Server("Engine Control Unit")
ecu_engine.inBoundary = vehicle_network_boundary
ecu_engine.OS = "RTOS"
ecu_engine.isHardened = True
ecu_engine.onAWS = False
ecu_engine.levels = [1]

ecu_brake = Server("Brake Control Unit")
ecu_brake.inBoundary = vehicle_network_boundary
ecu_brake.OS = "RTOS"
ecu_brake.isHardened = True
ecu_brake.onAWS = False
ecu_brake.levels = [1]

# Infotainment System Components
head_unit = Server("Head Unit")
head_unit.inBoundary = infotainment_boundary
head_unit.OS = "Android/Linux"
head_unit.isHardened = False
head_unit.onAWS = False
head_unit.levels = [2, 3]
head_unit.implementsAuthenticationScheme = True
head_unit.authorizesSource = True

bluetooth_module = Lambda("Bluetooth Module")
bluetooth_module.inBoundary = infotainment_boundary
bluetooth_module.onAWS = False
bluetooth_module.levels = [2]
bluetooth_module.implementsAuthenticationScheme = True

wifi_module = Lambda("WiFi Module")
wifi_module.inBoundary = infotainment_boundary
wifi_module.onAWS = False
wifi_module.levels = [2]
wifi_module.implementsAuthenticationScheme = True

cellular_modem = Lambda("4G/5G Modem")
cellular_modem.inBoundary = infotainment_boundary
cellular_modem.onAWS = False
cellular_modem.levels = [2]
cellular_modem.implementsAuthenticationScheme = True

usb_interface = Lambda("USB Interface")
usb_interface.inBoundary = infotainment_boundary
usb_interface.onAWS = False
usb_interface.levels = [3]

navigation_system = Server("Navigation System")
navigation_system.inBoundary = infotainment_boundary
navigation_system.OS = "Embedded Linux"
navigation_system.isHardened = False
navigation_system.onAWS = False
navigation_system.levels = [2]

# Data Stores
user_profiles = Datastore("User Profiles DB")
user_profiles.inBoundary = infotainment_boundary
user_profiles.type = "SQLite"
user_profiles.isEncrypted = True
user_profiles.inScope = True
user_profiles.levels = [2, 3]
user_profiles.isShared = False

media_storage = Datastore("Media Storage")
media_storage.inBoundary = infotainment_boundary
media_storage.type = "File System"
media_storage.isEncrypted = False
media_storage.inScope = True
media_storage.levels = [3]

navigation_data = Datastore("Navigation Maps")
navigation_data.inBoundary = infotainment_boundary
navigation_data.type = "File System"
navigation_data.isEncrypted = False
navigation_data.inScope = True
navigation_data.levels = [2]

# Define Dataflows

# User interactions
user_input = Dataflow(user, head_unit, "User Input Commands")
user_input.protocol = "Touch/Voice"
user_input.dstPort = 443
user_input.data = "Commands, Settings"
user_input.note = "User interacts with infotainment system"

display_output = Dataflow(head_unit, user, "Display Output")
display_output.protocol = "HDMI/Display"
display_output.dstPort = 443
display_output.data = "UI, Media, Navigation"

# Bluetooth connections
bt_pairing = Dataflow(mobile_device, bluetooth_module, "Bluetooth Pairing")
bt_pairing.protocol = "Bluetooth"
bt_pairing.dstPort = 1
bt_pairing.data = "Pairing Keys, Device Info"
bt_pairing.isEncrypted = True

bt_audio = Dataflow(bluetooth_module, head_unit, "Audio Stream")
bt_audio.protocol = "A2DP"
bt_audio.dstPort = 1
bt_audio.data = "Audio Data"

bt_phonebook = Dataflow(bluetooth_module, user_profiles, "Contact Sync")
bt_phonebook.protocol = "PBAP"
bt_phonebook.dstPort = 1
bt_phonebook.data = "Contacts, Call History"

# WiFi connections
wifi_hotspot = Dataflow(wifi_module, mobile_device, "WiFi Hotspot")
wifi_hotspot.protocol = "WiFi"
wifi_hotspot.dstPort = 443
wifi_hotspot.data = "Internet Traffic"
wifi_hotspot.isEncrypted = True

# Cellular connections
cloud_sync = Dataflow(cellular_modem, cloud_services, "Cloud Sync")
cloud_sync.protocol = "HTTPS"
cloud_sync.dstPort = 443
cloud_sync.data = "User Preferences, Diagnostics"
cloud_sync.isEncrypted = True

ota_updates = Dataflow(cloud_services, cellular_modem, "OTA Updates")
ota_updates.protocol = "HTTPS"
ota_updates.dstPort = 443
ota_updates.data = "Firmware, Maps, Software"
ota_updates.isEncrypted = True
ota_updates.authenticatedWith = True

# GPS data
gps_signal = Dataflow(gps_satellite, navigation_system, "GPS Signal")
gps_signal.protocol = "GPS"
gps_signal.dstPort = 1
gps_signal.data = "Location Data"
gps_signal.isEncrypted = False

nav_to_head = Dataflow(navigation_system, head_unit, "Navigation Data")
nav_to_head.protocol = "Internal API"
nav_to_head.dstPort = 443
nav_to_head.data = "Routes, POI, Traffic"

# USB connections
usb_media = Dataflow(user, usb_interface, "USB Media")
usb_media.protocol = "USB"
usb_media.dstPort = 1
usb_media.data = "Media Files, Data"

usb_to_storage = Dataflow(usb_interface, media_storage, "Media Transfer")
usb_to_storage.protocol = "File Transfer"
usb_to_storage.dstPort = 1
usb_to_storage.data = "Audio, Video Files"

# Vehicle network interactions
can_gateway = Dataflow(head_unit, can_bus, "CAN Gateway")
can_gateway.protocol = "CAN"
can_gateway.dstPort = 1
can_gateway.data = "Vehicle Status, Commands"
can_gateway.note = "Gateway between infotainment and vehicle network"

vehicle_status = Dataflow(can_bus, head_unit, "Vehicle Status")
vehicle_status.protocol = "CAN"
vehicle_status.dstPort = 1
vehicle_status.data = "Speed, Fuel, Diagnostics"

# Critical vehicle controls (these should be read-only from infotainment)
engine_data = Dataflow(ecu_engine, can_bus, "Engine Data")
engine_data.protocol = "CAN"
engine_data.dstPort = 1
engine_data.data = "RPM, Temperature, Status"

brake_data = Dataflow(ecu_brake, can_bus, "Brake Data")
brake_data.protocol = "CAN"
brake_data.dstPort = 1
brake_data.data = "Brake Status, ABS Data"

# Internal data flows
head_to_profiles = Dataflow(head_unit, user_profiles, "Profile Management")
head_to_profiles.protocol = "SQL"
head_to_profiles.dstPort = 3306
head_to_profiles.data = "User Settings, Preferences"

head_to_media = Dataflow(head_unit, media_storage, "Media Access")
head_to_media.protocol = "File System"
head_to_media.dstPort = 1
head_to_media.data = "Media Files"

nav_maps_access = Dataflow(navigation_system, navigation_data, "Map Data Access")
nav_maps_access.protocol = "File System"
nav_maps_access.dstPort = 1
nav_maps_access.data = "Map Tiles, POI Data"

# Process the threat model
tm.process()

# Generate reports
print("Generating threat model reports...")
print(f"Found {len(tm.findings)} potential threats")
print("\n" + "="*60)
print("THREAT FINDINGS:")
print("="*60 + "\n")

# Group findings by component
findings_by_component = {}
for finding in tm.findings:
    component = finding.target
    if component not in findings_by_component:
        findings_by_component[component] = []
    findings_by_component[component].append(finding)

# Print findings organized by component
for component, findings in findings_by_component.items():
    print(f"\n[{component}]")
    print("-" * 40)
    for finding in findings:
        print(f"• {finding.description}")
        print(f"  Severity: {finding.severity}")
        print(f"  Category: {finding.category}")
        print(f"  Details: {finding.details}")
        print()

# Generate summary statistics
print("\n" + "="*60)
print("SUMMARY STATISTICS:")
print("="*60)
threat_categories = {}
for finding in tm.findings:
    category = finding.category
    if category not in threat_categories:
        threat_categories[category] = 0
    threat_categories[category] += 1

for category, count in sorted(threat_categories.items()):
    print(f"{category}: {count} threats")

print(f"\nTotal threats identified: {len(tm.findings)}")

# Generate reports (uncomment to generate actual files)
# tm.report("infotainment_threat_report.html")  # HTML report
# tm.dfd()  # Generate DFD diagram (requires Graphviz)
