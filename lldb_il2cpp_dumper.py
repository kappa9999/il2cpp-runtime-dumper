#!/usr/bin/env python3
"""
Unity IL2CPP Metadata Dumper for iOS using LLDB
-----------------------------------------------
This script uses LLDB to attach to a Unity app and dump its IL2CPP metadata.
This approach is an alternative to the Frida-based method.
"""

import lldb
import os
import sys
import argparse
import time
import re
import struct
import shlex
from datetime import datetime

class IL2CPPDumper:
    def __init__(self, verbose=False):
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.target = None
        self.process = None
        self.verbose = verbose
        self.module_base = 0
        self.module_size = 0
        
    def log(self, message):
        """Print a log message"""
        print(f"[*] {message}")
        
    def log_verbose(self, message):
        """Print a verbose log message"""
        if self.verbose:
            print(f"[VERBOSE] {message}")
            
    def log_error(self, message):
        """Print an error message"""
        print(f"[-] ERROR: {message}")
        
    def log_success(self, message):
        """Print a success message"""
        print(f"[+] {message}")
    
    def attach_to_pid(self, pid):
        """Attach to a process by PID"""
        self.log(f"Attaching to process with PID {pid}")
        
        error = lldb.SBError()
        self.target = self.debugger.CreateTarget("")
        
        if not self.target:
            self.log_error("Failed to create target")
            return False
        
        self.process = self.target.AttachToProcessWithID(
            lldb.SBListener(), 
            pid,
            error
        )
        
        if not error.Success():
            self.log_error(f"Failed to attach to process: {error.GetCString()}")
            return False
            
        if self.process.GetState() != lldb.eStateStopped:
            self.log("Waiting for process to stop...")
            self.process.Stop()
            
        self.log_success(f"Attached to process {pid}")
        return True
    
    def attach_to_app(self, app_name):
        """Launch and attach to an app by bundle identifier"""
        self.log(f"Launching and attaching to app: {app_name}")
        
        # Use mobile device commands to launch the app
        launch_cmd = f"xcrun simctl launch booted {app_name}"
        
        try:
            import subprocess
            output = subprocess.check_output(launch_cmd, shell=True).decode('utf-8').strip()
            pid_match = re.search(r'(\d+)', output)
            
            if pid_match:
                pid = int(pid_match.group(1))
                self.log(f"App launched with PID: {pid}")
                return self.attach_to_pid(pid)
            else:
                self.log_error(f"Failed to get PID from launch output: {output}")
                return False
                
        except Exception as e:
            self.log_error(f"Failed to launch app: {e}")
            return False
    
    def find_il2cpp_module(self):
        """Find the IL2CPP module in the target process"""
        self.log("Looking for IL2CPP module...")
        
        for module in self.process.modules:
            module_name = module.file.basename
            
            if "libil2cpp.dylib" in module_name:
                self.module_base = module.GetLoadAddress()
                self.module_size = module.GetByteSize()
                self.log_success(f"Found IL2CPP module at 0x{self.module_base:x} (size: {self.module_size})")
                return module
            
        # Try alternative module names
        for module in self.process.modules:
            module_name = module.file.basename
            
            if "UnityFramework" in module_name:
                self.module_base = module.GetLoadAddress()
                self.module_size = module.GetByteSize()
                self.log_success(f"Found Unity framework at 0x{self.module_base:x} (size: {self.module_size})")
                return module
        
        self.log_error("Could not find IL2CPP module")
        return None
    
    def read_memory(self, address, size):
        """Read memory from the target process"""
        error = lldb.SBError()
        memory = self.process.ReadMemory(address, size, error)
        
        if error.Success():
            return memory
        else:
            self.log_verbose(f"Failed to read memory at 0x{address:x}: {error.GetCString()}")
            return None
    
    def find_bytes_in_memory(self, pattern, start_addr, size):
        """Find a byte pattern in memory"""
        self.log_verbose(f"Searching for pattern at 0x{start_addr:x}, size {size}")
        
        # Use LLDB's memory find command
        command = f"memory find -s '{pattern}' -c 1 -- {start_addr} {start_addr + size}"
        
        result = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(command, result)
        
        if result.Succeeded():
            output = result.GetOutput()
            address_match = re.search(r'data found at: (0x[0-9a-fA-F]+)', output)
            
            if address_match:
                address = int(address_match.group(1), 16)
                self.log_verbose(f"Found pattern at 0x{address:x}")
                return address
        
        return None
    
    def scan_memory_for_il2cpp_signature(self):
        """Scan memory for IL2CPP signature"""
        self.log("Scanning memory for IL2CPP signature")
        
        il2cpp_signature = "IL2CPP"
        
        # Create regions to scan
        regions_to_scan = []
        
        # First, check the main module
        if self.module_base and self.module_size:
            regions_to_scan.append((self.module_base, self.module_size))
        
        # Add other memory regions
        for region in self.get_memory_regions():
            if region not in regions_to_scan:
                regions_to_scan.append(region)
        
        # Scan each region
        for base, size in regions_to_scan:
            self.log_verbose(f"Scanning region 0x{base:x} - 0x{base+size:x} ({size} bytes)")
            
            addr = self.find_bytes_in_memory(il2cpp_signature, base, size)
            if addr:
                # Validate header
                if self.validate_metadata_header(addr):
                    size = self.estimate_metadata_size(addr)
                    self.log_success(f"Found valid IL2CPP metadata at 0x{addr:x} (size: {size})")
                    return addr, size
                else:
                    self.log_verbose(f"Found IL2CPP signature at 0x{addr:x} but header validation failed")
        
        return None, 0
    
    def get_memory_regions(self):
        """Get readable memory regions"""
        regions = []
        
        # Use the vmmap command to get memory regions
        result = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand("vmmap", result)
        
        if result.Succeeded():
            output = result.GetOutput()
            
            # Parse vmmap output to find readable regions
            for line in output.split('\n'):
                # Look for lines with read permission
                if 'r--' in line or 'r-x' in line or 'rw-' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_range = parts[0].split('-')
                        if len(addr_range) == 2:
                            try:
                                start = int(addr_range[0], 16)
                                end = int(addr_range[1], 16)
                                size = end - start
                                
                                # Skip small regions
                                if size > 4096:
                                    regions.append((start, size))
                            except ValueError:
                                pass
        
        return regions
    
    def validate_metadata_header(self, address):
        """Validate if address points to IL2CPP metadata header"""
        # Read potential header
        header = self.read_memory(address, 20)
        if not header:
            return False
        
        # Check for IL2CPP signature
        if header[:6] != b'IL2CPP':
            return False
        
        # Check version (should be reasonable)
        version = struct.unpack('<H', header[6:8])[0]
        if version < 1 or version > 100:
            return False
        
        self.log_success(f"Validated IL2CPP metadata with version {version}")
        return True
    
    def estimate_metadata_size(self, address):
        """Estimate the size of metadata starting at address"""
        header = self.read_memory(address, 16)
        if not header:
            return 0
        
        # Try common offsets for size field
        size_offsets = [8, 12, 16]
        
        for offset in size_offsets:
            if len(header) >= offset + 4:
                size = struct.unpack('<I', header[offset:offset+4])[0]
                
                # Sanity check - metadata should be reasonable size
                if size > 1024 and size < 100 * 1024 * 1024:
                    return size
        
        # If we can't determine size from header, use a reasonable default
        return 20 * 1024 * 1024  # 20MB
    
    def find_metadata_file(self):
        """Try to find the global-metadata.dat file in filesystem"""
        self.log("Looking for global-metadata.dat file...")
        
        # Get app bundle path
        bundle_path = self.get_app_bundle_path()
        if not bundle_path:
            self.log_verbose("Could not determine app bundle path")
            return None
        
        # Check common locations
        metadata_paths = [
            os.path.join(bundle_path, "Data", "Managed", "Metadata", "global-metadata.dat"),
            os.path.join(bundle_path, "global-metadata.dat"),
            os.path.join(bundle_path, "Data", "metadata", "global-metadata.dat"),
            os.path.join(bundle_path, "Contents", "Data", "Managed", "Metadata", "global-metadata.dat")
        ]
        
        for path in metadata_paths:
            if os.path.exists(path):
                self.log_success(f"Found metadata file at {path}")
                return path
        
        self.log_verbose("Could not find metadata file in filesystem")
        return None
    
    def get_app_bundle_path(self):
        """Try to determine the app bundle path"""
        # Get the main executable path
        main_executable = self.process.executable.fullpath
        if not main_executable:
            return None
        
        # App bundle is typically the directory containing the executable
        return os.path.dirname(main_executable)
    
    def dump_metadata(self, output_file):
        """Dump the IL2CPP metadata to a file"""
        self.log(f"Attempting to dump IL2CPP metadata to {output_file}")
        
        # First check if metadata file exists in filesystem
        metadata_file = self.find_metadata_file()
        if metadata_file:
            import shutil
            try:
                shutil.copy2(metadata_file, output_file)
                self.log_success(f"Copied metadata file to {output_file}")
                return True
            except Exception as e:
                self.log_error(f"Failed to copy metadata file: {e}")
        
        # If file not found, look for metadata in memory
        module = self.find_il2cpp_module()
        if not module:
            self.log_error("Could not find IL2CPP module")
            return False
        
        # Scan memory for IL2CPP signature
        metadata_addr, metadata_size = self.scan_memory_for_il2cpp_signature()
        
        if metadata_addr and metadata_size > 0:
            # Read metadata from memory
            metadata_bytes = self.read_memory(metadata_addr, metadata_size)
            
            if metadata_bytes:
                try:
                    with open(output_file, 'wb') as f:
                        f.write(metadata_bytes)
                    
                    self.log_success(f"Dumped {len(metadata_bytes)} bytes of metadata to {output_file}")
                    return True
                except Exception as e:
                    self.log_error(f"Failed to write metadata file: {e}")
                    return False
            else:
                self.log_error("Failed to read metadata from memory")
                return False
        else:
            self.log_error("Could not find IL2CPP metadata in memory")
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        if self.process and self.process.IsValid():
            self.process.Continue()
        
        lldb.SBDebugger.Destroy(self.debugger)
        self.log("Cleanup complete")


def main():
    parser = argparse.ArgumentParser(description="Unity IL2CPP Metadata Dumper using LLDB")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-n", "--app-name", help="Bundle identifier of the target application")
    target_group.add_argument("-P", "--attach-pid", type=int, help="PID of the running process to attach to")
    
    parser.add_argument("-o", "--output", default="metadata.dat", help="Output file for metadata (default: metadata.dat)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Initialize dumper
    dumper = IL2CPPDumper(verbose=args.verbose)
    
    try:
        # Attach to target
        if args.app_name:
            if not dumper.attach_to_app(args.app_name):
                return 1
        elif args.attach_pid:
            if not dumper.attach_to_pid(args.attach_pid):
                return 1
        
        # Dump metadata
        if dumper.dump_metadata(args.output):
            print(f"\nMetadata successfully dumped to {args.output}")
            return 0
        else:
            print("\nFailed to dump metadata")
            return 1
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        # Cleanup
        dumper.cleanup()

if __name__ == "__main__":
    sys.exit(main()) 