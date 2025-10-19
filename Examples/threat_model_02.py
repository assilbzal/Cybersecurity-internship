#!/usr/bin/env python3

from pytm import TM, Server, Dataflow, Boundary, Actor, ExternalEntity

# Create threat model
tm = TM("Simple Vehicle Infotainment")
tm.description = "Basic threat model for vehicle infotainment"

# Define boundaries
internet = Boundary("Internet")
car = Boundary("Car")

# External entities
driver = Actor("Driver")
driver.inBoundary = car

phone = ExternalEntity("Smartphone")
phone.inBoundary = internet

cloud = ExternalEntity("Cloud Server")
cloud.inBoundary = internet

# Main components
infotainment = Server("Infotainment System")
infotainment.inBoundary = car
infotainment.OS = "Android"

vehicle_bus = Server("Vehicle CAN Bus")
vehicle_bus.inBoundary = car
vehicle_bus.OS = "Embedded"
vehicle_bus.isHardened = True

# Data flows
# Driver interactions
touch_input = Dataflow(driver, infotainment, "Touch Input")
touch_input.data = "Commands"

display = Dataflow(infotainment, driver, "Display")
display.data = "Screen Content"

# Phone connection
bluetooth = Dataflow(phone, infotainment, "Bluetooth Connection")
bluetooth.protocol = "Bluetooth"
bluetooth.data = "Music, Calls, Contacts"
bluetooth.isEncrypted = True

# Internet connection
updates = Dataflow(cloud, infotainment, "Software Updates")
updates.protocol = "HTTPS"
updates.data = "Firmware, Maps"
updates.isEncrypted = True

telemetry = Dataflow(infotainment, cloud, "Vehicle Data")
telemetry.protocol = "HTTPS"
telemetry.data = "Diagnostics, Location"
telemetry.isEncrypted = True

# Vehicle connection
vehicle_data = Dataflow(vehicle_bus, infotainment, "Vehicle Info")
vehicle_data.protocol = "CAN"
vehicle_data.data = "Speed, Fuel, Status"

control_commands = Dataflow(infotainment, vehicle_bus, "Control Commands")
control_commands.protocol = "CAN"
control_commands.data = "Settings, Requests"

# Process the model
tm.process()

# Print results
print("="*50)
print("VEHICLE INFOTAINMENT THREAT MODEL")
print("="*50)
print(f"\nTotal threats found: {len(tm.findings)}\n")

for finding in tm.findings:
    print(f"Threat: {finding.description}")
    print(f"Target: {finding.target}")
    print(f"Severity: {finding.severity}")
    print("-"*30)
