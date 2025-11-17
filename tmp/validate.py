import json
import re

filename = 'output-latest.json'

try:
    with open(filename, 'r') as file:
        captures = json.load(file)
except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{filename}'.")

# Too lazy, generated using ChatGPT, works fine for libsodium v1.0.20
pattern = r"""
^
(?:const\s+)?                             # optional leading const

(?:
      void
    | char
    | unsigned\s+char
    | signed\s+char
    | short
    | unsigned\s+short
    | int
    | unsigned\s+int
    | long
    | unsigned\s+long
    | long\s+long
    | unsigned\s+long\s+long
    | float
    | double
    | long\s+double
    | _?Bool
    | u?int(?:8|16|32|64)_t              # stdint types
)

(?:\s+const)?                             # optional trailing const

(?:                                       # pointer chain
    \s*\*+\s*(?:const)?                   # one pointer layer, optional const
)*

\s*
(?:\[\s*\d*\s*\])?                        # optional array: [], [N], [ANY]

(?:\s*\(\s*\*\s*\)\s*\([^()]*\))?         # optional function pointer

$
"""

primitive_regex = re.compile(pattern, re.VERBOSE)

def is_primitive(t: str) -> bool:
    return primitive_regex.match(t)

def sanitize_type_for_validation (param_type: str) -> str:
    sanitized = param_type.removesuffix(" *")
    sanitized = sanitized.removeprefix("const ")
    return sanitized

struct_names = {item["name"] for item in captures if item["capture"] == "struct"}
typedef_names = {item["name"] for item in captures if item["capture"] == "typedef"}

errors = []

for item in captures:
    if item["capture"] == "function":
        func_name = item["name"]

        for param in item.get("params", []):
            ptype = sanitize_type_for_validation(param["type"])

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
