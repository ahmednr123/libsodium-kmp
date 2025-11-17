import json
import re

filename = 'output.json'

try:
    with open(filename, 'r') as file:
        captures = json.load(file)
except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{filename}'.")


PRIMITIVES = {"int", "long", "float", "double", "char", "string", "bool", "void"}

def is_primitive(t: str) -> bool:
    return any(p in t for p in PRIMITIVES)

def sanitize_type (param_type: str) -> str:
    sanitized = param_type.replace(" *", "")
    sanitized = sanitized.replace("const ", "")
    return sanitized

struct_names = {item["name"] for item in captures if item["capture"] == "struct"}
typedef_names = {item["name"] for item in captures if item["capture"] == "typedef"}

errors = []

for item in captures:
    if item["capture"] == "function":
        func_name = item["name"]

        for param in item.get("params", []):
            ptype = sanitize_type(param["type"])

            if is_primitive(ptype):
                continue

            if ptype not in struct_names and ptype not in typedef_names:
                errors.append(
                    f"Error: Function '{func_name}' has parameter '{param['name']}' "
                    f"with unknown type '{ptype}'"
                )

if errors:
    for e in errors:
        print(e)
    raise ValueError("Validator: Function param validation check failed")
else:
    print("Validator: Function param validation check completed successfully")
