# Unity IL2CPP Metadata Dumper for iOS

A tool for dumping metadata from IL2CPP-compiled Unity apps on jailbroken iOS devices at runtime. This tool can extract function names, offsets, and other important metadata from any Unity app.

## Features

- Dump IL2CPP metadata from any running Unity app on jailbroken iOS
- Two dumping methods available:
  - Frida-based dumping (more dynamic, works with heavily protected apps)
  - LLDB-based dumping (more reliable, uses native debugging)
- Extract function names, class names, and offsets
- Works with obfuscated Unity games
- Multiple approaches to locate and extract metadata
- Handles various Unity/IL2CPP versions
- Comprehensive metadata parsing and analysis

## Requirements

- Jailbroken iOS device
- Python 3.6 or higher
- For Frida method:
  - Frida (`pip install frida frida-tools`)
  - `frida-server` installed and running on the iOS device
- For LLDB method:
  - LLDB Python bindings
  - Proper debugging permissions/entitlements

## Installation

1. Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

2. For Frida method: Make sure `frida-server` is running on your jailbroken iOS device. You can download it from the [Frida releases page](https://github.com/frida/frida/releases).

3. For LLDB method: Ensure you have LLDB installed and configured properly:
   - On macOS, it comes with Xcode
   - On other platforms, install the LLDB Python bindings

4. Clone this repository or download the files to your computer.

## Usage

### Using Frida Method

#### List all installed applications
```bash
python unity_il2cpp_dumper.py -U -l
```

#### List all running processes
```bash
python unity_il2cpp_dumper.py -U -p
```

#### Dump metadata from a Unity app by bundle identifier
```bash
python unity_il2cpp_dumper.py -U -n com.example.unityapp -o metadata.dat
```

#### Attach to a running process by PID
```bash
python unity_il2cpp_dumper.py -U -P 1234 -o metadata.dat
```

### Using LLDB Method

#### Dump metadata from a running process by PID
```bash
python lldb_il2cpp_dumper.py -P 1234 -o metadata.dat
```

#### Dump metadata from an app by bundle identifier
```bash
python lldb_il2cpp_dumper.py -n com.example.unityapp -o metadata.dat
```

### Parsing the Metadata

After dumping the metadata, you can parse and analyze it using the metadata parser:

#### Generate a human-readable report
```bash
python metadata_parser.py metadata.dat -o report.txt
```

#### Export metadata as JSON
```bash
python metadata_parser.py metadata.dat -j metadata.json
```

### All-in-One Helper Script

Use the helper script to dump and parse in one step:

```bash
python dump_and_parse.py -U -n com.example.unityapp -o metadata.dat --report-output report.txt
```

## Command-line Arguments

### Frida Dumper (unity_il2cpp_dumper.py)
- `-l`, `--list-apps`: List all installed applications
- `-p`, `--list-processes`: List all running processes
- `-n`, `--app-name`: Bundle identifier of the target application
- `-P`, `--attach-pid`: PID of the running process to attach to
- `-o`, `--output`: Output file for the metadata (default: metadata.dat)
- `-U`, `--usb`: Connect to USB device
- `-R`, `--remote`: Connect to remote device (IP:PORT)
- `-v`, `--verbose`: Enable verbose logging

### LLDB Dumper (lldb_il2cpp_dumper.py)
- `-n`, `--app-name`: Bundle identifier of the target application
- `-P`, `--attach-pid`: PID of the running process to attach to
- `-o`, `--output`: Output file for metadata (default: metadata.dat)
- `-v`, `--verbose`: Enable verbose logging

### Metadata Parser (metadata_parser.py)
- `-o`, `--output`: Output file for the report (default: stdout)
- `-j`, `--json`: Export metadata as JSON to specified file

## How It Works

### Frida Method
The Frida-based dumper:
1. Injects JavaScript code into the target Unity app
2. Locates the IL2CPP module in memory
3. Searches for metadata registration
4. Extracts metadata from memory or filesystem
5. Saves the metadata to a file

### LLDB Method
The LLDB-based dumper:
1. Attaches to the target process using LLDB
2. Maps the process memory
3. Locates the IL2CPP module
4. Scans for metadata in memory or filesystem
5. Dumps the metadata to a file

Both methods employ several strategies to locate the metadata:
- Looking for exported IL2CPP functions
- Searching for known string patterns
- Scanning memory for the IL2CPP signature
- Examining reference chains to locate metadata structures

## Choosing Between Frida and LLDB

- Use Frida when:
  - The app has complex protections
  - You need dynamic instrumentation
  - You want to hook into specific functions
  - The app actively checks for debuggers

- Use LLDB when:
  - You need reliable memory access
  - The app blocks Frida
  - You want to use native debugging capabilities
  - You need to set breakpoints or inspect memory more thoroughly

## Troubleshooting

### Metadata Not Found

If the tool fails to find the metadata, try these steps:

1. Use the `-v` flag to enable verbose logging
2. Try both Frida and LLDB methods
3. Make sure the app is actually a Unity app compiled with IL2CPP
4. Try attaching to the process after it has fully started
5. If using Frida, check if the app has anti-Frida measures
6. If using LLDB, ensure you have proper debugging permissions

### Connection Issues

For Frida:
1. Ensure frida-server is running on the device
2. Check USB connection or network connectivity
3. Verify the correct IP and port for remote connections
4. Try restarting frida-server

For LLDB:
1. Verify debugging permissions
2. Check if the process is accessible
3. Ensure proper entitlements are in place
4. Try running with elevated privileges

## Analyzing the Dumped Metadata

The dumped metadata.dat file can be analyzed with:

- The included metadata_parser.py script
- [Il2CppInspector](https://github.com/djkaty/Il2CppInspector)
- [IDA Pro](https://hex-rays.com/ida-pro/) with IL2CPP plugins
- [Ghidra](https://ghidra-sre.org/) with appropriate scripts

## License

This project is for educational purposes only. Use responsibly and only on applications you own or have permission to analyze.

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always respect intellectual property rights and the terms of service of the applications you analyze. 