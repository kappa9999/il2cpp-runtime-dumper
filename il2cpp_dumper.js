/*
 * IL2CPP Metadata Dumper for Unity Apps on iOS
 * -------------------------------------------
 * This script locates and dumps IL2CPP metadata from a running Unity app.
 */

(function() {
    'use strict';

    // Configuration (will be overridden by Python script)
    var config = {
        verbose: false,
        outputFile: "metadata.dat"
    };

    // Logging utilities
    function log(message) {
        send({type: "log", message: message});
    }

    function logVerbose(message) {
        if (config.verbose) {
            log("[VERBOSE] " + message);
        }
    }

    function logStatus(message) {
        send({type: "status", message: message});
    }

    function logError(message, error) {
        if (error) {
            send({type: "log", message: `ERROR: ${message}: ${error}`});
        } else {
            send({type: "log", message: `ERROR: ${message}`});
        }
    }

    // Memory utilities
    function readMemory(address, size) {
        try {
            return Memory.readByteArray(ptr(address), size);
        } catch (e) {
            logError(`Failed to read memory at ${address} (size: ${size})`, e);
            return null;
        }
    }

    function findPattern(pattern, mask, start, size) {
        logVerbose(`Searching for pattern at ${start} with size ${size}`);
        
        const ranges = Process.enumerateRangesSync({
            protection: 'r--',
            coalesce: true
        }).filter(range => {
            return range.base.compare(ptr(start)) >= 0 && 
                  range.base.add(range.size).compare(ptr(start).add(size)) <= 0;
        });

        for (const range of ranges) {
            logVerbose(`Scanning range: ${range.base} - ${range.base.add(range.size)} (${range.size} bytes)`);
            
            const address = Memory.scanSync(range.base, range.size, pattern, mask);
            if (address.length > 0) {
                return address[0].address;
            }
        }
        
        return null;
    }

    // Unity/IL2CPP specific functions
    function findIl2CppModule() {
        logStatus("Looking for the libil2cpp.dylib module...");
        
        const modules = Process.enumerateModulesSync();
        for (const module of modules) {
            if (module.name.includes("libil2cpp.dylib")) {
                logStatus(`Found IL2CPP module at ${module.base} (size: ${module.size})`);
                return module;
            }
        }
        
        // Try alternative approaches if direct module lookup fails
        for (const module of modules) {
            if (module.name.includes("UnityFramework")) {
                logStatus(`Found Unity framework at ${module.base} (size: ${module.size})`);
                return module;
            }
        }
        
        logError("Could not find IL2CPP module");
        return null;
    }

    function findMetadataRegistration(il2cppModule) {
        logStatus("Searching for IL2CPP metadata registration...");
        
        // References to key strings that help us find the metadata
        const metadataSignatures = [
            { pattern: "MetadataRegistration", symbol: "g_MetadataRegistration" },
            { pattern: "CodeRegistration", symbol: "g_CodeGenRegistration" }
        ];
        
        for (const sig of metadataSignatures) {
            try {
                const symbol = Module.findExportByName(il2cppModule.name, sig.symbol);
                if (symbol !== null) {
                    logStatus(`Found ${sig.symbol} at ${symbol}`);
                    return symbol;
                }
            } catch (e) {
                logVerbose(`Could not find export ${sig.symbol}: ${e}`);
            }
        }
        
        logStatus("Could not find metadata registration through exports, trying pattern scanning...");
        
        // If we couldn't find the symbol directly, try to search for the metadata header
        // These patterns may need adjustment based on the Unity version
        const patterns = [
            // Common IL2CPP metadata patterns
            { pattern: [0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x4C, 0x32, 0x43, 0x50, 0x50], mask: "x????????xxxxx" },
            { pattern: [0x49, 0x4C, 0x32, 0x43, 0x50, 0x50, 0x00, 0x00], mask: "xxxxxx??" }
        ];
        
        for (const p of patterns) {
            const address = findPattern(p.pattern, p.mask, il2cppModule.base, il2cppModule.size);
            if (address !== null) {
                logStatus(`Found potential metadata header at ${address}`);
                return address;
            }
        }
        
        logError("Could not find metadata registration through pattern scanning");
        return null;
    }

    function findAndDumpMetadata() {
        logStatus("Starting IL2CPP metadata dumping process...");
        
        // Find the IL2CPP module
        const il2cppModule = findIl2CppModule();
        if (!il2cppModule) {
            return false;
        }
        
        // Try to find the metadata_registration
        const metadataPtr = findMetadataRegistration(il2cppModule);
        if (!metadataPtr) {
            // If we can't find it directly, try a more aggressive search approach
            return dumpMetadataAggressively(il2cppModule);
        }
        
        // Now let's locate the global-metadata.dat in memory
        logStatus("Searching for global-metadata.dat in memory...");
        
        // First check common paths in the filesystem (for iOS)
        const possiblePaths = [
            "/var/containers/Bundle/Application/*//*.app/Data/Managed/Metadata/global-metadata.dat",
            "/private/var/containers/Bundle/Application/*//*.app/Data/Managed/Metadata/global-metadata.dat",
            "/var/mobile/Containers/Data/Application/*/Documents/global-metadata.dat",
            Process.mainModule.path.replace(/\/[^\/]+$/, "") + "/Data/Managed/Metadata/global-metadata.dat",
            Process.mainModule.path.replace(/\/[^\/]+$/, "") + "/global-metadata.dat"
        ];
        
        for (const path of possiblePaths) {
            try {
                const expanded = path.includes("*") ? 
                    glob(path) : 
                    (File.exists(path) ? [path] : []);
                    
                for (const file of expanded) {
                    logStatus(`Checking metadata file at: ${file}`);
                    if (File.exists(file)) {
                        logStatus(`Found metadata file: ${file}`);
                        const metadataBytes = File.readAllBytes(file);
                        saveMetadata(metadataBytes);
                        return true;
                    }
                }
            } catch (e) {
                logVerbose(`Error checking path ${path}: ${e}`);
            }
        }
        
        // If we can't find the file, try to locate it in memory
        return scanMemoryForMetadata(il2cppModule);
    }

    function scanMemoryForMetadata(il2cppModule) {
        logStatus("Scanning memory for IL2CPP metadata...");
        
        // Metadata header pattern: "IL2CPP" signature
        const il2cppSignature = [0x49, 0x4C, 0x32, 0x43, 0x50, 0x50];
        const mask = "xxxxxx";
        
        const ranges = Process.enumerateRangesSync({
            protection: 'r--',
            coalesce: true
        });
        
        for (const range of ranges) {
            if (range.size < 100) continue; // Skip small allocations
            
            logVerbose(`Scanning range: ${range.base} - ${range.base.add(range.size)} (${range.size} bytes)`);
            
            const matches = Memory.scanSync(range.base, range.size, il2cppSignature, mask);
            for (const match of matches) {
                logStatus(`Potential metadata header found at ${match.address}`);
                
                try {
                    // Read a small header to validate
                    const header = Memory.readByteArray(match.address, 20);
                    const headerHex = Array.from(new Uint8Array(header))
                                         .map(b => b.toString(16).padStart(2, '0'))
                                         .join(' ');
                    logVerbose(`Header bytes: ${headerHex}`);
                    
                    // Validate if this looks like IL2CPP metadata
                    // This requires knowledge of the IL2CPP metadata header structure
                    // We're looking for the "IL2CPP" string followed by metadata version info
                    if (validateMetadataHeader(match.address)) {
                        // If it looks valid, try to determine the size and dump it
                        const metadataSize = estimateMetadataSize(match.address, range.base.add(range.size));
                        if (metadataSize > 0) {
                            logStatus(`Found metadata of size ${metadataSize} bytes`);
                            const metadataBytes = Memory.readByteArray(match.address, metadataSize);
                            saveMetadata(metadataBytes);
                            return true;
                        }
                    }
                } catch (e) {
                    logVerbose(`Error examining potential metadata at ${match.address}: ${e}`);
                    continue;
                }
            }
        }
        
        logError("Could not find metadata in memory");
        return false;
    }

    function validateMetadataHeader(address) {
        try {
            // Check for "IL2CPP" signature
            const signature = Memory.readUtf8String(address, 6);
            if (signature !== "IL2CPP") {
                return false;
            }
            
            // Try to read metadata version (expected to be a reasonable value)
            const version = Memory.readInt(address.add(6));
            if (version < 1 || version > 100) {
                return false;
            }
            
            logStatus(`Metadata validated: signature "${signature}", version ${version}`);
            return true;
        } catch (e) {
            return false;
        }
    }

    function estimateMetadataSize(startAddress, maxAddress) {
        // The metadata size is usually stored in the header
        // Typically at offset 8 or 12 depending on the IL2CPP version
        try {
            // Try to read size from common offsets
            const sizeOffsets = [8, 12, 16];
            for (const offset of sizeOffsets) {
                const size = Memory.readUInt(startAddress.add(offset));
                // Sanity check: metadata size should be reasonable (>1KB, <100MB)
                if (size > 1024 && size < 100 * 1024 * 1024) {
                    return size;
                }
            }
            
            // If we can't determine the size from the header, use a heuristic approach
            // Scan for the end of the metadata section
            const bufSize = 4096;
            let currentOffset = 1024; // Start checking after a reasonable header size
            
            while (startAddress.add(currentOffset).compare(maxAddress) < 0) {
                if (currentOffset > 100 * 1024 * 1024) {
                    logError("Metadata seems unreasonably large, limiting size");
                    return 50 * 1024 * 1024; // Return a safe upper limit
                }
                
                try {
                    Memory.readByteArray(startAddress.add(currentOffset), bufSize);
                    currentOffset += bufSize;
                } catch (e) {
                    // If we can't read at this offset, we might have hit the end
                    logVerbose(`Potential end of metadata at offset ${currentOffset}`);
                    return currentOffset;
                }
            }
            
            // Fallback to a reasonable default if all else fails
            return 20 * 1024 * 1024; // 20MB as a reasonable upper bound
            
        } catch (e) {
            logError(`Error estimating metadata size: ${e}`);
            return 0;
        }
    }

    function dumpMetadataAggressively(il2cppModule) {
        logStatus("Attempting aggressive metadata search...");
        
        // This is a more extensive search for games that might have obfuscated IL2CPP structure
        const il2cppBaseRange = Process.enumerateRangesSync({
            protection: 'r-x',
            coalesce: true
        }).filter(range => {
            return range.base.equals(il2cppModule.base);
        })[0];
        
        if (!il2cppBaseRange) {
            logError("Could not find IL2CPP module memory range");
            return false;
        }
        
        // Look for known function exports that might lead us to metadata
        const knownFunctions = [
            "il2cpp_init",
            "il2cpp_runtime_class_init",
            "il2cpp_object_new",
            "il2cpp_method_get_name",
            "il2cpp_class_get_methods"
        ];
        
        let foundFunc = null;
        for (const funcName of knownFunctions) {
            foundFunc = Module.findExportByName(il2cppModule.name, funcName);
            if (foundFunc) {
                logStatus(`Found function: ${funcName} at ${foundFunc}`);
                break;
            }
        }
        
        if (!foundFunc) {
            // If we can't find known exports, try to find strings that are commonly used
            const commonStrings = [
                "UnityEngine",
                "GameObject",
                "Transform",
                "MonoBehaviour",
                "UnityEngine.CoreModule"
            ];
            
            for (const str of commonStrings) {
                const results = Memory.scanSync(il2cppModule.base, il2cppModule.size, 
                                              Array.from(str).map(c => c.charCodeAt(0)).concat(0), 
                                              "x".repeat(str.length + 1));
                
                if (results.length > 0) {
                    logStatus(`Found string reference to "${str}" at ${results[0].address}`);
                    // Now search for references to this string
                    const stringAddr = results[0].address;
                    const references = findReferencesToAddress(stringAddr, il2cppModule.base, il2cppModule.size);
                    
                    if (references.length > 0) {
                        logStatus(`Found ${references.length} references to "${str}"`);
                        // These references might lead us to metadata structures
                        return scanNearReferences(references, il2cppModule);
                    }
                }
            }
        }
        
        // Fallback to full memory scan
        return scanMemoryForMetadata(il2cppModule);
    }

    function findReferencesToAddress(targetAddr, baseAddr, size) {
        const references = [];
        const targetAddrValue = targetAddr.toUInt32();
        
        const ranges = Process.enumerateRangesSync({
            protection: 'r--',
            coalesce: true
        }).filter(range => {
            return range.base.compare(ptr(baseAddr)) >= 0 && 
                  range.base.add(range.size).compare(ptr(baseAddr).add(size)) <= 0;
        });
        
        for (const range of ranges) {
            const rangeSize = range.size;
            const rangeBase = range.base;
            
            // Scan for 4-byte aligned addresses that might be pointers to our target
            for (let offset = 0; offset < rangeSize - 4; offset += 4) {
                try {
                    const value = Memory.readUInt(rangeBase.add(offset));
                    if (value === targetAddrValue) {
                        references.push(rangeBase.add(offset));
                    }
                } catch (e) {
                    // Skip if we can't read this memory
                }
            }
        }
        
        return references;
    }

    function scanNearReferences(references, il2cppModule) {
        // Look near the references for potential metadata structures
        for (const ref of references) {
            // Scan around the reference (both before and after)
            const scanWindow = 1024 * 16; // 16KB window
            const startScan = ref.sub(scanWindow);
            const endScan = ref.add(scanWindow);
            
            // Make sure we're still within the module
            const adjustedStart = startScan.compare(il2cppModule.base) < 0 ? il2cppModule.base : startScan;
            const adjustedEnd = endScan.compare(il2cppModule.base.add(il2cppModule.size)) > 0 ? 
                               il2cppModule.base.add(il2cppModule.size) : endScan;
            
            // IL2CPP signature to look for
            const il2cppSignature = [0x49, 0x4C, 0x32, 0x43, 0x50, 0x50];
            const scanSize = adjustedEnd.sub(adjustedStart).toUInt32();
            
            try {
                const matches = Memory.scanSync(adjustedStart, scanSize, il2cppSignature, "xxxxxx");
                
                if (matches.length > 0) {
                    logStatus(`Found IL2CPP signature near reference at ${matches[0].address}`);
                    
                    if (validateMetadataHeader(matches[0].address)) {
                        const metadataSize = estimateMetadataSize(matches[0].address, adjustedEnd);
                        if (metadataSize > 0) {
                            logStatus(`Found metadata of size ${metadataSize} bytes`);
                            const metadataBytes = Memory.readByteArray(matches[0].address, metadataSize);
                            saveMetadata(metadataBytes);
                            return true;
                        }
                    }
                }
            } catch (e) {
                logVerbose(`Error scanning near reference ${ref}: ${e}`);
            }
        }
        
        return scanMemoryForMetadata(il2cppModule);
    }

    function saveMetadata(metadataBytes) {
        logStatus(`Saving metadata to ${config.outputFile}`);
        send({type: "metadata", filename: config.outputFile}, metadataBytes);
    }

    // Helper function to expand globs (simple implementation)
    function glob(pattern) {
        const files = [];
        
        try {
            // Simple glob implementation for iOS
            // Replace * with .* for regex
            const regexPattern = new RegExp("^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
            
            // Get the directory part before the first wildcard
            const firstWildcard = pattern.indexOf("*");
            const firstQuestion = pattern.indexOf("?");
            const wildPos = (firstWildcard !== -1 && firstQuestion !== -1) ?
                            Math.min(firstWildcard, firstQuestion) :
                            (firstWildcard !== -1 ? firstWildcard : firstQuestion);
            
            let basePath = "/";
            if (wildPos !== -1) {
                const lastSlash = pattern.lastIndexOf("/", wildPos);
                if (lastSlash !== -1) {
                    basePath = pattern.substring(0, lastSlash);
                }
            } else {
                basePath = pattern;
            }
            
            logVerbose(`Base path for glob: ${basePath}`);
            
            // Function to recursively list directories matching pattern
            function listDir(path, remainingDepth = 5) {
                if (remainingDepth <= 0) return;
                
                try {
                    const entries = File.listDirectory(path);
                    for (const entry of entries) {
                        const fullPath = path + "/" + entry;
                        
                        try {
                            if (regexPattern.test(fullPath)) {
                                files.push(fullPath);
                            }
                            
                            // Recurse into subdirectories if path contains more wildcards
                            if (remainingDepth > 0 && fullPath.indexOf("/") !== -1) {
                                listDir(fullPath, remainingDepth - 1);
                            }
                        } catch (e) {
                            // Skip entries we can't access
                        }
                    }
                } catch (e) {
                    logVerbose(`Error listing directory ${path}: ${e}`);
                }
            }
            
            // Start recursive listing from base path
            if (File.exists(basePath) && basePath !== pattern) {
                listDir(basePath);
            } else {
                // Fallback to checking the exact path
                if (File.exists(pattern)) {
                    files.push(pattern);
                }
            }
        } catch (e) {
            logError(`Error in glob pattern matching: ${e}`);
        }
        
        return files;
    }

    // Main function
    function main() {
        logStatus("IL2CPP Metadata Dumper started");
        
        // Register to receive configuration
        recv("config", function(message) {
            Object.assign(config, message.data);
            logStatus(`Configuration updated: verbose=${config.verbose}, outputFile=${config.outputFile}`);
            
            // Start the dumping process
            if (findAndDumpMetadata()) {
                logStatus("Metadata dumping completed successfully");
            } else {
                logError("Failed to dump metadata");
            }
        });
        
        logStatus("Waiting for configuration...");
    }

    // Start the script
    main();
})(); 