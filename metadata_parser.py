#!/usr/bin/env python3
"""
Unity IL2CPP Metadata Parser
----------------------------
This script parses the binary metadata.dat file dumped by the unity_il2cpp_dumper.py
and produces a readable output with function names, offsets, and other details.
"""

import sys
import os
import struct
import argparse
import json
from collections import namedtuple

# IL2CPP Metadata Structures
# Based on Unity IL2CPP runtime code
Il2CppGlobalMetadataHeader = namedtuple('Il2CppGlobalMetadataHeader', [
    'signature',
    'version',
    'stringLiteralDataOffset',
    'stringLiteralDataCount',
    'stringLiteralOffset',
    'stringLiteralCount',
    'genericContainersOffset',
    'genericContainersCount',
    'nestedTypesOffset',
    'nestedTypesCount',
    'interfacesOffset',
    'interfacesCount',
    'vtableMethodsOffset',
    'vtableMethodsCount',
    'interfaceOffsetsOffset',
    'interfaceOffsetsCount',
    'typeDefinitionsOffset',
    'typeDefinitionsCount',
    'imagesOffset',
    'imagesCount',
    'assembliesOffset',
    'assembliesCount',
    'fieldsOffset',
    'fieldsCount',
    'genericParametersOffset',
    'genericParametersCount',
    'fieldAndParameterDefaultValueDataOffset',
    'fieldAndParameterDefaultValueDataCount',
    'fieldMarshaledSizesOffset',
    'fieldMarshaledSizesCount',
    'parametersOffset',
    'parametersCount',
    'fieldsRefs',
    'fieldsRefsCount',
    'eventsOffset',
    'eventsCount',
    'propertiesOffset',
    'propertiesCount',
    'methodsOffset',
    'methodsCount',
    'parameterDefaultValuesOffset',
    'parameterDefaultValuesCount',
    'fieldDefaultValuesOffset',
    'fieldDefaultValuesCount',
    'methodSpecsOffset',
    'methodSpecsCount',
    'genericMethodInstsOffset',
    'genericMethodInstsCount',
])

class Il2CppMethodDefinition:
    def __init__(self, data, offset):
        self.nameIndex = struct.unpack('<I', data[offset:offset+4])[0]
        self.declaringType = struct.unpack('<I', data[offset+4:offset+8])[0]
        self.returnType = struct.unpack('<I', data[offset+8:offset+12])[0]
        self.parameterStart = struct.unpack('<I', data[offset+12:offset+16])[0]
        self.genericContainerIndex = struct.unpack('<I', data[offset+16:offset+20])[0]
        self.methodIndex = struct.unpack('<I', data[offset+20:offset+24])[0]
        self.invokerIndex = struct.unpack('<I', data[offset+24:offset+28])[0]
        self.delegateWrapperIndex = struct.unpack('<I', data[offset+28:offset+32])[0]
        self.rgctxStartIndex = struct.unpack('<I', data[offset+32:offset+36])[0]
        self.rgctxCount = struct.unpack('<I', data[offset+36:offset+40])[0]
        self.token = struct.unpack('<I', data[offset+40:offset+44])[0]
        self.flags = struct.unpack('<H', data[offset+44:offset+46])[0]
        self.iflags = struct.unpack('<H', data[offset+46:offset+48])[0]
        self.slot = struct.unpack('<H', data[offset+48:offset+50])[0]
        self.parameterCount = struct.unpack('<H', data[offset+50:offset+52])[0]

class Il2CppTypeDefinition:
    def __init__(self, data, offset):
        self.nameIndex = struct.unpack('<I', data[offset:offset+4])[0]
        self.namespaceIndex = struct.unpack('<I', data[offset+4:offset+8])[0]
        self.customAttributeIndex = struct.unpack('<I', data[offset+8:offset+12])[0]
        self.byvalTypeIndex = struct.unpack('<I', data[offset+12:offset+16])[0]
        self.byrefTypeIndex = struct.unpack('<I', data[offset+16:offset+20])[0]
        
        # Array of type indexes
        self.declaringTypeIndex = struct.unpack('<I', data[offset+20:offset+24])[0]
        self.parentIndex = struct.unpack('<I', data[offset+24:offset+28])[0]
        self.elementTypeIndex = struct.unpack('<I', data[offset+28:offset+32])[0]
        
        # rgctx
        self.rgctxStartIndex = struct.unpack('<I', data[offset+32:offset+36])[0]
        self.rgctxCount = struct.unpack('<I', data[offset+36:offset+40])[0]
        
        # Fields and methods
        self.fieldStart = struct.unpack('<I', data[offset+40:offset+44])[0]
        self.methodStart = struct.unpack('<I', data[offset+44:offset+48])[0]
        self.eventStart = struct.unpack('<I', data[offset+48:offset+52])[0]
        self.propertyStart = struct.unpack('<I', data[offset+52:offset+56])[0]
        self.nestedTypesStart = struct.unpack('<I', data[offset+56:offset+60])[0]
        self.interfacesStart = struct.unpack('<I', data[offset+60:offset+64])[0]
        self.vtableStart = struct.unpack('<I', data[offset+64:offset+68])[0]
        self.interfaceOffsetsStart = struct.unpack('<I', data[offset+68:offset+72])[0]
        
        # Counts
        self.method_count = struct.unpack('<H', data[offset+72:offset+74])[0]
        self.property_count = struct.unpack('<H', data[offset+74:offset+76])[0]
        self.field_count = struct.unpack('<H', data[offset+76:offset+78])[0]
        self.event_count = struct.unpack('<H', data[offset+78:offset+80])[0]
        self.nested_type_count = struct.unpack('<H', data[offset+80:offset+82])[0]
        self.interface_count = struct.unpack('<H', data[offset+82:offset+84])[0]
        self.vtable_count = struct.unpack('<H', data[offset+84:offset+86])[0]
        self.interface_offsets_count = struct.unpack('<H', data[offset+86:offset+88])[0]
        
        # bits
        self.bitfield = struct.unpack('<I', data[offset+88:offset+92])[0]
        self.token = struct.unpack('<I', data[offset+92:offset+96])[0]

class MetadataParser:
    def __init__(self, metadata_file):
        with open(metadata_file, 'rb') as f:
            self.data = f.read()
        
        self.parse_header()
        self.parse_strings()
        
    def parse_header(self):
        # Verify IL2CPP signature
        if self.data[0:6].decode('utf-8') != 'IL2CPP':
            raise ValueError("Invalid metadata file: missing IL2CPP signature")
        
        # Parse header
        header_size = struct.calcsize('<6sHIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII')
        header_data = struct.unpack('<6sHIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', self.data[0:header_size])
        
        self.header = Il2CppGlobalMetadataHeader(
            signature=header_data[0].decode('utf-8'),
            version=header_data[1],
            stringLiteralDataOffset=header_data[2],
            stringLiteralDataCount=header_data[3],
            stringLiteralOffset=header_data[4],
            stringLiteralCount=header_data[5],
            genericContainersOffset=header_data[6],
            genericContainersCount=header_data[7],
            nestedTypesOffset=header_data[8],
            nestedTypesCount=header_data[9],
            interfacesOffset=header_data[10],
            interfacesCount=header_data[11],
            vtableMethodsOffset=header_data[12],
            vtableMethodsCount=header_data[13],
            interfaceOffsetsOffset=header_data[14],
            interfaceOffsetsCount=header_data[15],
            typeDefinitionsOffset=header_data[16],
            typeDefinitionsCount=header_data[17],
            imagesOffset=header_data[18],
            imagesCount=header_data[19],
            assembliesOffset=header_data[20],
            assembliesCount=header_data[21],
            fieldsOffset=header_data[22],
            fieldsCount=header_data[23],
            genericParametersOffset=header_data[24],
            genericParametersCount=header_data[25],
            fieldAndParameterDefaultValueDataOffset=header_data[26],
            fieldAndParameterDefaultValueDataCount=header_data[27],
            fieldMarshaledSizesOffset=header_data[28],
            fieldMarshaledSizesCount=header_data[29],
            parametersOffset=header_data[30],
            parametersCount=header_data[31],
            fieldsRefs=header_data[32],
            fieldsRefsCount=header_data[33],
            eventsOffset=header_data[34],
            eventsCount=header_data[35],
            propertiesOffset=header_data[36],
            propertiesCount=header_data[37],
            methodsOffset=header_data[38],
            methodsCount=header_data[39],
            parameterDefaultValuesOffset=header_data[40],
            parameterDefaultValuesCount=header_data[41],
            fieldDefaultValuesOffset=header_data[42],
            fieldDefaultValuesCount=header_data[43],
            methodSpecsOffset=header_data[44],
            methodSpecsCount=header_data[45],
            genericMethodInstsOffset=header_data[46],
            genericMethodInstsCount=header_data[47],
        )
        
        print(f"IL2CPP Metadata Version: {self.header.version}")
        print(f"Methods Count: {self.header.methodsCount}")
        print(f"Types Count: {self.header.typeDefinitionsCount}")
    
    def parse_strings(self):
        # Parse string literals
        self.strings = {}
        string_data_offset = self.header.stringLiteralOffset
        string_data_end = string_data_offset + self.header.stringLiteralCount * 8
        
        # Create a dictionary of string index -> string value
        current_offset = string_data_offset
        string_index = 0
        
        while current_offset < len(self.data):
            string_end = self.data.find(b'\0', current_offset)
            if string_end == -1:
                break
                
            string_value = self.data[current_offset:string_end].decode('utf-8', errors='replace')
            self.strings[string_index] = string_value
            string_index += 1
            current_offset = string_end + 1
    
    def get_string(self, index):
        """Get string by index from the string table"""
        offset = self.header.stringLiteralOffset
        
        # Navigate to the string start
        while index > 0:
            offset = self.data.find(b'\0', offset) + 1
            if offset == 0:
                return "<string not found>"
            index -= 1
        
        # Find string end
        end = self.data.find(b'\0', offset)
        if end == -1:
            return "<string end not found>"
        
        # Extract and return the string
        return self.data[offset:end].decode('utf-8', errors='replace')
    
    def parse_types(self):
        """Parse and return all type definitions"""
        types = []
        offset = self.header.typeDefinitionsOffset
        type_size = 96  # Size of Il2CppTypeDefinition structure
        
        for i in range(self.header.typeDefinitionsCount):
            type_def = Il2CppTypeDefinition(self.data, offset)
            types.append({
                'name': self.get_string(type_def.nameIndex),
                'namespace': self.get_string(type_def.namespaceIndex),
                'methods_start': type_def.methodStart,
                'method_count': type_def.method_count,
                'fields_start': type_def.fieldStart,
                'field_count': type_def.field_count,
                'token': hex(type_def.token)
            })
            offset += type_size
        
        return types
    
    def parse_methods(self):
        """Parse and return all method definitions"""
        methods = []
        offset = self.header.methodsOffset
        method_size = 52  # Size of Il2CppMethodDefinition structure
        
        for i in range(self.header.methodsCount):
            method_def = Il2CppMethodDefinition(self.data, offset)
            methods.append({
                'name': self.get_string(method_def.nameIndex),
                'declaring_type': method_def.declaringType,
                'parameter_count': method_def.parameterCount,
                'parameter_start': method_def.parameterStart,
                'token': hex(method_def.token),
                'index': method_def.methodIndex
            })
            offset += method_size
        
        return methods
    
    def generate_report(self, output_file=None):
        """Generate a human-readable report of the metadata"""
        types = self.parse_types()
        methods = self.parse_methods()
        
        # Group methods by declaring type
        methods_by_type = {}
        for method in methods:
            type_index = method['declaring_type']
            if type_index not in methods_by_type:
                methods_by_type[type_index] = []
            methods_by_type[type_index].append(method)
        
        # Build the report
        report = []
        report.append(f"IL2CPP Metadata Report")
        report.append(f"====================")
        report.append(f"Metadata Version: {self.header.version}")
        report.append(f"Total Types: {len(types)}")
        report.append(f"Total Methods: {len(methods)}")
        report.append("\n")
        
        # Sort types by namespace and name for better readability
        sorted_types = sorted(types, key=lambda t: (t['namespace'], t['name']))
        
        for type_def in sorted_types:
            full_name = f"{type_def['namespace']}.{type_def['name']}" if type_def['namespace'] else type_def['name']
            report.append(f"Type: {full_name} (Token: {type_def['token']})")
            
            # Get methods for this type
            type_index = types.index(type_def)
            type_methods = methods_by_type.get(type_index, [])
            
            # Sort methods by name
            sorted_methods = sorted(type_methods, key=lambda m: m['name'])
            
            for method in sorted_methods:
                report.append(f"  Method: {method['name']} (Token: {method['token']}, Index: {method['index']})")
            
            report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report written to {output_file}")
        else:
            print(report_text)
        
        return report_text
    
    def export_json(self, output_file):
        """Export metadata as JSON"""
        types = self.parse_types()
        methods = self.parse_methods()
        
        # Prepare data for JSON export
        data = {
            "metadata_version": self.header.version,
            "types": types,
            "methods": methods
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        print(f"JSON data exported to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="IL2CPP Metadata Parser")
    parser.add_argument("metadata_file", help="Path to the metadata.dat file")
    parser.add_argument("-o", "--output", help="Output file for the report (default: stdout)")
    parser.add_argument("-j", "--json", help="Export metadata as JSON to the specified file")
    
    args = parser.parse_args()
    
    try:
        parser = MetadataParser(args.metadata_file)
        
        if args.json:
            parser.export_json(args.json)
        else:
            parser.generate_report(args.output)
            
    except Exception as e:
        print(f"Error parsing metadata: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 