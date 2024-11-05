import json
import pandas as pd
from tabulate import tabulate

# Define the input file path
input_file_path = 'sbom.json'

# Read the CycloneDX SBOM JSON file
with open(input_file_path, 'r') as infile:
    sbom_data = json.load(infile)

# Function to extract the component details
def extract_component_details(components):
    extracted_data = []
    for component in components:
        name = component.get("name")
        version = component.get("version")
        author = component.get("author", "Unknown")  # Default to 'Unknown' if not present
        component_type = component.get("type", "Unknown")  # Default to 'Unknown' if not present

        extracted_data.append({
            "name": name,
            "version": version,
            "author": author,
            "type": component_type
        })
    return extracted_data

# Extract components from the SBOM data
components = sbom_data.get("components", [])
extracted_data = extract_component_details(components)

# Load extracted data into a pandas DataFrame
df = pd.DataFrame(extracted_data)

# Print the DataFrame using tabulate for a more human-readable format
print(tabulate(df, headers='keys', tablefmt='psql'))
