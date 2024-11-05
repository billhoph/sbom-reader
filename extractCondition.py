import json
import pandas as pd
from packaging import version
from tabulate import tabulate

# Define the input file path
input_file_path = 'cve.json'

# Read the JSON file
with open(input_file_path, 'r') as infile:
    json_data = [json.loads(line) for line in infile]

# Load JSON data into a pandas DataFrame
df = pd.DataFrame(json_data)

# Function to check if a version satisfies the conditions
def check_version_applied(package_version, conditions):
    for condition_group in conditions:
        all_conditions_met = True
        for cond in condition_group:
            op, ver = cond[0], cond[1:]
            if op == '\u003c' and not version.parse(package_version) < version.parse(ver):
                all_conditions_met = False
            elif op == '\u003c=' and not version.parse(package_version) <= version.parse(ver):
                all_conditions_met = False
            elif op == '\u003e' and not version.parse(package_version) > version.parse(ver):
                all_conditions_met = False
            elif op == '\u003e=' and not version.parse(package_version) >= version.parse(ver):
                all_conditions_met = False
        if all_conditions_met:
            return True
    return False

# Example: Validate if a particular package version is applied
package_name = "fam"
package_version = "2.9.6"

# package_name = "mysql"
# package_version = "5.6.2"


filtered_df = df[df['package'] == package_name]
filtered_df['is_version_applied'] = filtered_df['conditions'].apply(lambda cond: check_version_applied(package_version, cond))
filtered_df = filtered_df[['cve','distro','distro_release','package','type','cvss','conditions','is_version_applied']]

# Display the DataFrame using tabulate for a more human-readable format
print(tabulate(filtered_df, headers='keys', tablefmt='psql'))
