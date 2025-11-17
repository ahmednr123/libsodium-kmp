import os
import sys
from clang.cindex import Config, CursorKind, Index, TranslationUnit
from pprint import pprint
import json
import re



########################################################
#                 Parse header files                  #
########################################################


Config.set_library_file("/usr/lib/llvm-20/lib/libclang-20.so.1")

header_files_path = sys.argv[1]
export_file_source = ""
with open(os.path.join(header_files_path, "export.h"), "r") as file:
    export_file_source = file.read()

def is_not_current_file (cursor, filename):
    loc = cursor.location
    return loc.file and loc.file.name != filename

def get_h_files_in_directory(directory_path):
    files = []
    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)
        if entry.endswith('.h') and os.path.isfile(full_path):
            files.append(entry)
    return files

captures = []

def is_typedef_imp (typedef_type, name):
    if "struct " in typedef_type:
        struct_name = typedef_type.split(" ")[1]
        if name == struct_name:
            return False
    return True

def parse_cursor (cursor, filename):
    if is_not_current_file(cursor, filename):
        return

    if cursor.kind == CursorKind.TYPEDEF_DECL:
        name = cursor.spelling
        typedef_type = cursor.underlying_typedef_type.spelling
        if typedef_type == "int":
            tokens = " ".join(token.spelling for token in cursor.get_tokens())
            raise ValueError("Found a typedef type with 'int' being mapped, seems unlikely, check libsodium codebase\n"
                             "This usually means that a specific header file is not included\n"
                             "If false error (and tokens contain an 'int'), remove this check\n"
                             f"Tokens captured: {tokens}")
            exit(0)
        if is_typedef_imp(typedef_type, name):
            captures.append({"capture": "typedef", "type": typedef_type, "name": name})
        return
    if cursor.kind == CursorKind.STRUCT_DECL and cursor.is_definition():
        fields = []
        for field in cursor.get_children():
            if field.kind == CursorKind.FIELD_DECL:
                fields.append({"type": field.type.spelling, "name": field.spelling})
        captures.append({"capture": "struct", "name": cursor.spelling or "<anonymous>", "fields": fields})
        return
    if cursor.kind == CursorKind.FUNCTION_DECL:
        params = []
        for param in cursor.get_children():
            if param.kind == CursorKind.PARM_DECL:
                params.append({"type": param.type.spelling, "name": param.spelling})
        captures.append({"capture": "function", "return_type": cursor.result_type.spelling, "name": cursor.spelling, "params": params})
        return

    for c in cursor.get_children():
        parse_cursor(c, filename)

files = get_h_files_in_directory(sys.argv[1])

for filename in files:
    if filename == "export.h":
        continue

    file_handle = open(os.path.join(header_files_path,filename), "r")
    source = file_handle.read()

    #source = "#define size_t int\n" + source
    #source.replace('#include "export.h"', export_file_source)

    index = Index.create()
    print('Parsing file:', filename)
    tu = index.parse(filename, args=[f"-I{header_files_path}"], unsaved_files=[(filename, source)], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    parse_cursor(tu.cursor, filename)
    file_handle.close()


with open("output-latest.json", "w") as json_file:
    json.dump(captures, json_file, indent=4)


########################################################
#                     Validation                       #
########################################################


# Too lazy, generated using ChatGPT, works fine for libsodium v1.0.20
primitive_pattern = r"""
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
    | size_t
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

primitive_regex = re.compile(primitive_pattern, re.VERBOSE)

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



########################################################
#           Swig interface file generation             #
########################################################



