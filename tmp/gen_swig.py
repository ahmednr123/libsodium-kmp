import json

filename = 'output-latest.json'

try:
    with open(filename, 'r') as file:
        captures = json.load(file)
except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{filename}'.")

# Add typemap using structs
for capture_obj in captures:
    if capture_obj.capture == "typedef":
        exit(0)

# Add typemap using typdefs


# Add functions
