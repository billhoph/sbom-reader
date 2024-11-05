import json
import pandas as pd
from tabulate import tabulate

# Define the input file path
input_file_path = 'cve.json'

# Load JSON data into a pandas DataFrame
df = pd.read_json(input_file_path, lines=True)

# Print the DataFrame using tabulate for a more human-readable format
print(tabulate(df, headers='keys', tablefmt='psql'))

# Example search: Filter by severity 'medium'
# filtered_df = df[df['severity'] == 'medium']
# print(tabulate(filtered_df, headers='keys', tablefmt='psql'))
