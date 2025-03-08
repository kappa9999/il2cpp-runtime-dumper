#!/usr/bin/env python3
import frida
import sys
import os
import argparse
import time
import json

# JavaScript to be injected into the target process
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "il2cpp_dumper.js"), "r") as f:
    FRIDA_SCRIPT = f.read()

def on_message(message, data):
    """Callback for handling messages from the JavaScript."""
    if message["type"] == "send":
        payload = message["payload"]
        if isinstance(payload, dict):
            if payload.get("type") == "log":
                print(f"[LOG] {payload['message']}")
            elif payload.get("type") == "metadata":
                print(f"[+] Received metadata dump, saving to {payload['filename']}")
                with open(payload["filename"], "wb") as f:
                    f.write(data)
                print(f"[+] Metadata saved successfully ({len(data)} bytes)")
            elif payload.get("type") == "status":
                print(f"[STATUS] {payload['message']}")
        else:
            print(f"[*] {payload}")
    elif message["type"] == "error":
        print(f"[-] Error: {message['stack']}")

def list_applications(device):
    """List all applications on the device."""
    print("Available applications:")
    for app in device.enumerate_applications():
        print(f"  {app.identifier} ({app.name})")

def list_running_processes(device):
    """List all running processes on the device."""
    print("Running processes:")
    for process in device.enumerate_processes():
        print(f"  {process.pid}: {process.name}")

def main():
    parser = argparse.ArgumentParser(description="Unity IL2CPP Metadata Dumper for jailbroken iOS")
    
    # Main operation modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-l", "--list-apps", action="store_true", help="List all installed applications")
    mode_group.add_argument("-p", "--list-processes", action="store_true", help="List all running processes")
    mode_group.add_argument("-n", "--app-name", help="Bundle identifier of the target application")
    mode_group.add_argument("-P", "--attach-pid", type=int, help="PID of the running process to attach to")
    
    # Additional options
    parser.add_argument("-o", "--output", default="metadata.dat", help="Output file for the metadata (default: metadata.dat)")
    parser.add_argument("-U", "--usb", action="store_true", help="Connect to USB device")
    parser.add_argument("-R", "--remote", help="Connect to remote device (IP:PORT)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Connect to device
    try:
        if args.remote:
            print(f"[*] Connecting to remote device at {args.remote}...")
            device = frida.get_device_manager().add_remote_device(args.remote)
        elif args.usb:
            print("[*] Connecting to USB device...")
            device = frida.get_usb_device()
        else:
            print("[*] Using local device...")
            device = frida.get_local_device()
        
        print(f"[+] Connected to {device.name}")
    except Exception as e:
        print(f"[-] Failed to connect to device: {e}")
        return 1
    
    # Handle different operation modes
    try:
        if args.list_apps:
            list_applications(device)
            return 0
        
        if args.list_processes:
            list_running_processes(device)
            return 0
        
        # Set up script configuration
        script_config = {
            "verbose": args.verbose,
            "outputFile": args.output
        }
        
        # Attach to target
        if args.app_name:
            print(f"[*] Spawning {args.app_name}...")
            pid = device.spawn([args.app_name])
            session = device.attach(pid)
            print(f"[+] Attached to {args.app_name} (PID: {pid})")
            
            # Create script
            script = session.create_script(FRIDA_SCRIPT)
            script.on("message", on_message)
            print("[*] Script loaded")
            
            # Load script and resume app
            script.load()
            script.post({"type": "config", "data": script_config})
            device.resume(pid)
            
        elif args.attach_pid:
            print(f"[*] Attaching to PID {args.attach_pid}...")
            session = device.attach(args.attach_pid)
            print(f"[+] Attached to process with PID {args.attach_pid}")
            
            # Create script
            script = session.create_script(FRIDA_SCRIPT)
            script.on("message", on_message)
            print("[*] Script loaded")
            
            # Load script
            script.load()
            script.post({"type": "config", "data": script_config})
        
        print("[*] Press Ctrl+C to stop the script")
        sys.stdin.read()
        
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 