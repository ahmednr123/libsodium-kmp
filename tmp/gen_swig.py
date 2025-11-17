import json
from pprint import pprint
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

primitive_regex = re.compile(pattern, re.VERBOSE)

def is_primitive(t: str) -> bool:
    return primitive_regex.match(t)

def sanitize_type (param_type: str) -> str:
    sanitized = param_type.removeprefix("const ")
    sanitized = re.sub(r"\[.*\]", "[0]", sanitized)
    return sanitized

types = set()
types_supported = set({
    'char *',
    'char **const',
    'char *const',
    'char[0]',
    'int',
    'size_t',
    'size_t *const',
    'size_t *',
    'int *',
    'int *const',
    'uint32_t',
    'uint64_t',
    'uint8_t *',
    'unsigned char',
    'unsigned char *',
    'unsigned char *const',
    'unsigned char[0]',
    'unsigned long long',
    'unsigned long long *',
    'void',
    'void (*)(void)',
    'void *',
    'void *const'
})

for capture_obj in captures:
    if capture_obj["capture"] == "function":
        func_name = capture_obj["name"]
        return_type = sanitize_type(capture_obj["return_type"])

        types.add(return_type)

        for param in capture_obj.get("params", []):
            ptype = sanitize_type(param["type"])

            # I am too laz
            if not is_primitive(ptype):
                continue

            types.add(ptype)

unsupported = types - types_supported
if unsupported:
    raise ValueError(f"Unsupported types: {unsupported}")

# Using https://github.com/joshjdevl/libsodium-jni/blob/master/jni/sodium.i
primitive_mappings = """
%module Sodium

%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"
%include "java.swg"

/* Basic mappings */
%apply int {unsigned long long};
%apply long[] {unsigned long long *};
%apply int {size_t};
%apply int {uint32_t};
%apply long {uint64_t};

/* unsigned char */
%typemap(jni) unsigned char *       "jbyteArray"
%typemap(jtype) unsigned char *     "byte[]"
%typemap(jstype) unsigned char *    "byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) unsigned char *"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""

/* uint8_t */
%typemap(jni) uint8_t *"jbyteArray"
%typemap(jtype) uint8_t *"byte[]"
%typemap(jstype) uint8_t *"byte[]"
%typemap(in) uint8_t *{
    $1 = (uint8_t *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) uint8_t *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) uint8_t *"$javainput"
%typemap(freearg) uint8_t *""

/* Strings */
%typemap(jni) char *"jbyteArray"
%typemap(jtype) char *"byte[]"
%typemap(jstype) char *"byte[]"
%typemap(in) char *{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *"$javainput"
%typemap(freearg) char *""


/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *BYTE "$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) char *BYTE ""

/* Fixed size strings/char arrays */
%typemap(jni) char [ANY]"jbyteArray"
%typemap(jtype) char [ANY]"byte[]"
%typemap(jstype) char [ANY]"byte[]"
%typemap(in) char [ANY]{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char [ANY]{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char [ANY]"$javainput"
%typemap(freearg) char [ANY]""

"""

def write_typemap (type_name):
    return """
    /*
        {name}
    */
    %typemap(jni) {name} *"jbyteArray"
    %typemap(jtype) {name} *"byte[]"
    %typemap(jstype) {name} *"byte[]"
    %typemap(in) {name} *{{
        $1 = ({name} *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }}
    %typemap(argout) {name} *{{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }}
    %typemap(javain) {name} *"$javainput"
    %typemap(freearg) {name} *""

    """.format(name=type_name)

crypto_mappings = """
/* =============================================================================

    TYPEMAPS FOR CRYPTO_*_STATE DATATYPES

============================================================================= */

"""

# Add typemap using typedef

for capture_obj in captures:
    if capture_obj["capture"] == "typedef":
        crypto_mappings += write_typemap(capture_obj["name"])

# Add typemap using struct

for capture_obj in captures:
    if capture_obj["capture"] == "struct":
        crypto_mappings += write_typemap(capture_obj["name"])

# Add functions

high_level_apis = """
/* *****************************************************************************

    HIGH-LEVEL LIBSODIUM API'S

***************************************************************************** */

"""

def conv_type(t):
    return re.sub(r'char\[\d+\]', 'char *', t)

def is_wildcard(params):
    for param in params:
        if param["type"] == "void (*)(void)":
            return True
    return False

def write_function (return_type, name, params):
    func_code = f"{return_type} {name}("
    if len(params) == 0:
        func_code += "void);\n\n"
        return func_code
    elif len(params) == 1:
        func_code += f"{conv_type(params[0]['type'])} {params[0]['name']});\n\n"
        return func_code
    else:
        for idx, param in enumerate(params):
            func_code += f"{'' if idx == 0 else '\t\t\t'}{conv_type(params[0]['type'])} {param['name']},\n"
        func_code = func_code.removesuffix(',\n') + ");\n\n"
        return func_code

for capture_obj in captures:
    if capture_obj["capture"] == "function":
        if not is_wildcard(capture_obj["params"]):
            high_level_apis += write_function(capture_obj["return_type"], capture_obj["name"], capture_obj["params"])


swig_interface_source = f"{primitive_mappings}\n{crypto_mappings}\n{high_level_apis}\n"

with open("sodium.i", "w") as file:
    file.write(swig_interface_source)
