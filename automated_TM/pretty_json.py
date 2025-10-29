import json

# Load the minified JSON
with open("vehicle_infotiainment_report.json") as f:
    data = json.load(f)

# Write it back in a pretty format
with open("vehicle_infotiainment_report_pretty.json", "w") as f:
    json.dump(data, f, indent=4)

print("Pretty JSON saved to vehicle_infotiainment_report_pretty.json")
