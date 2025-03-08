#!/usr/bin/env python3
"""
Unity IL2CPP Metadata Dump and Parse
-----------------------------------
This script combines the functionality of unity_il2cpp_dumper.py, lldb_il2cpp_dumper.py,
and metadata_parser.py to make it easier to dump and analyze IL2CPP metadata in one step.
"""

import os
import sys
import argparse
import subprocess
import time
import tempfile

def run_dumper(args):
    """Run the selected IL2CPP dumper with the provided arguments"""
    # Choose dumper based on method
    if args.method == "lldb":
        dumper_script = "lldb_il2cpp_dumper.py"
        dumper_cmd = [sys.executable, dumper_script]
    else:
        dumper_script = "unity_il2cpp_dumper.py"
        dumper_cmd = [sys.executable, dumper_script]
        
        if args.usb:
            dumper_cmd.append('-U')
        
        if args.remote:
            dumper_cmd.extend(['-R', args.remote])
    
    if args.app_name:
        dumper_cmd.extend(['-n', args.app_name])
    
    if args.attach_pid:
        dumper_cmd.extend(['-P', str(args.attach_pid)])
    
    if args.verbose:
        dumper_cmd.append('-v')
    
    # Use temp file for metadata output if needed
    if args.temp_metadata:
        metadata_file = os.path.join(tempfile.gettempdir(), 'il2cpp_metadata.dat')
    else:
        metadata_file = args.metadata_output
    
    dumper_cmd.extend(['-o', metadata_file])
    
    print(f"Running dumper ({args.method}): {' '.join(dumper_cmd)}")
    
    dumper_process = subprocess.Popen(dumper_cmd)
    
    try:
        # Wait for the dumper to complete or for user to cancel
        print("Dumping metadata... (Press Ctrl+C to stop)")
        dumper_process.wait()
        
        # Check if dumper completed successfully
        if dumper_process.returncode != 0:
            print(f"Dumper exited with return code {dumper_process.returncode}")
            return None
        
        # Verify metadata file exists
        if not os.path.exists(metadata_file):
            print(f"Metadata file {metadata_file} was not created")
            return None
        
        print(f"Metadata dumped to {metadata_file}")
        return metadata_file
        
    except KeyboardInterrupt:
        print("\nCancelled by user")
        dumper_process.terminate()
        return None

def run_parser(metadata_file, args):
    """Run the metadata parser with the provided arguments"""
    parser_cmd = [sys.executable, 'metadata_parser.py', metadata_file]
    
    if args.report_output:
        parser_cmd.extend(['-o', args.report_output])
    
    if args.json_output:
        parser_cmd.extend(['-j', args.json_output])
    
    print(f"Running parser: {' '.join(parser_cmd)}")
    
    try:
        # Run the parser and capture its output
        parser_result = subprocess.run(parser_cmd, 
                                      check=True, 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE,
                                      text=True)
        
        # Print parser stdout if not saved to a file
        if not args.report_output:
            print(parser_result.stdout)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Parser failed with return code {e.returncode}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Unity IL2CPP Metadata Dump and Parse Tool")
    
    # App targeting options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-n", "--app-name", help="Bundle identifier of the target application")
    target_group.add_argument("-P", "--attach-pid", type=int, help="PID of the running process to attach to")
    target_group.add_argument("-l", "--list-apps", action="store_true", help="List all installed applications and exit")
    target_group.add_argument("-p", "--list-processes", action="store_true", help="List all running processes and exit")
    
    # Device connection options (Frida only)
    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument("-U", "--usb", action="store_true", help="Connect to USB device (Frida only)")
    device_group.add_argument("-R", "--remote", help="Connect to remote device IP:PORT (Frida only)")
    
    # Method selection
    parser.add_argument("-m", "--method", choices=["frida", "lldb"], default="frida",
                       help="Dumping method to use (default: frida)")
    
    # Output options
    parser.add_argument("-M", "--metadata-output", default="metadata.dat", 
                        help="Output file for raw metadata (default: metadata.dat)")
    parser.add_argument("-o", "--report-output", 
                        help="Output file for the parsed report (default: print to console)")
    parser.add_argument("-j", "--json-output", 
                        help="Export parsed metadata as JSON to the specified file")
    
    # Other options
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-t", "--temp-metadata", action="store_true", 
                       help="Use temporary file for metadata dump (useful if only parsed output is needed)")
    parser.add_argument("--dump-only", action="store_true", 
                       help="Only dump metadata, don't parse")
    
    args = parser.parse_args()
    
    # Handle list operations
    if args.list_apps or args.list_processes:
        if args.method == "lldb":
            print("Listing apps/processes is only supported with Frida method")
            return 1
            
        dumper_cmd = [sys.executable, 'unity_il2cpp_dumper.py']
        
        if args.usb:
            dumper_cmd.append('-U')
        
        if args.remote:
            dumper_cmd.extend(['-R', args.remote])
            
        if args.list_apps:
            dumper_cmd.append('-l')
        else:
            dumper_cmd.append('-p')
            
        subprocess.run(dumper_cmd)
        return 0
    
    # Validate arguments
    if args.method == "lldb" and (args.usb or args.remote):
        print("Warning: USB/Remote options are ignored when using LLDB method")
    
    # Run the dumper
    metadata_file = run_dumper(args)
    
    if not metadata_file:
        return 1
    
    # Exit here if only dumping
    if args.dump_only:
        print(f"Dump completed. Metadata file: {metadata_file}")
        return 0
    
    # Run the parser
    print("\nParsing metadata...")
    success = run_parser(metadata_file, args)
    
    # Clean up temporary metadata file if used
    if args.temp_metadata and os.path.exists(metadata_file):
        try:
            os.remove(metadata_file)
            print(f"Temporary metadata file {metadata_file} removed")
        except:
            print(f"Warning: Could not remove temporary metadata file {metadata_file}")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 