# mac-registration-provider Project Guide

## Project Overview
This is a Go service that generates iMessage registration data on macOS. It provides registration codes for use with Beeper Mini when Beeper Cloud access is unavailable.

## Architecture
- **Main service**: Connects to websocket relay server for registration requests
- **NAC module**: Native macOS code for accessing private IDS framework functions
- **Offset management**: Handles different macOS version compatibility via hardcoded memory offsets

## Key Files
- `main.go` - Entry point and CLI argument handling
- `relay.go` - WebSocket relay mode (default, works with Beeper)
- `submit.go` - Periodic submission mode
- `generate.go` - Core registration data generation
- `nac/` - Native Access Control implementation
  - `nac.go` - Go interface to C functions
  - `nac.m` - Objective-C NAC implementation
  - `offsets.go` - macOS version-specific memory offsets
- `versions/versions.go` - macOS version detection
- `requests/requests.go` - HTTP request utilities

## Current Work Context
You're working on the `find-offset-test` branch, focusing on:
- Adding offsets for macOS versions (14.4.1, 14.5, 14.6 b1)
- Testing offset verification methods
- Investigating macOS 15 Sequoia compatibility issues

## Build & Development

### Prerequisites
- macOS (required for testing, uses private IDS framework)
- Go 1.21+
- Xcode command line tools (for Objective-C compilation)

### Build Commands
```bash
# Build the binary
go build -o mac-registration-provider

# Or use the build script
./build.sh
```

### Testing
```bash
# Test with compatibility check
./mac-registration-provider -check-compatibility

# Generate single registration (test mode)
./mac-registration-provider -once

# Run with specific relay server
./mac-registration-provider -relay-server https://custom-server.com
```

### Key Development Commands
```bash
# Check binary hash (for offset verification)
shasum -a 256 /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd

# Check for reference symbol
nm --defined-only --extern-only --arch=arm64e /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd | grep IDSProtoKeyTransparencyTrustedServiceReadFrom

# Verify system version
sw_vers
```

## Dependencies
- `github.com/tidwall/gjson` - JSON parsing
- `howett.net/plist` - Property list handling  
- `nhooyr.io/websocket` - WebSocket client

## macOS Version Support Status
- **Supported**: 10.14.6, 10.15.1-10.15.7, 11.5-11.7, 12.7.1, 13.3.1, 13.5-13.6.4, 14.0-14.6
- **Unsupported**: macOS 15+ Sequoia (requires reverse engineering new offsets)

## Recent Changes Made
1. Added offsets for macOS 14.5 in `nac/offsets.go`
2. Added offsets for macOS 14.6 beta 1
3. Added offsets for macOS 14.4.1
4. Created `verify_offsets.md` documentation for offset verification methods

## Known Issues
- macOS 15 Sequoia not supported (automatic offset finder fails, manual reverse engineering needed)
- Offset verification requires specific error code (-44023) from sanity check
- Binary hash verification needed for each new macOS version

## Development Workflow
1. Identify target macOS version needing support
2. Get binary hash using `shasum -a 256`
3. Find offsets using disassembler or pattern matching
4. Add offsets to `nac/offsets.go`
5. Test with sanity check and actual registration generation
6. Commit changes following conventional commit format

## Security Notes
- Uses private macOS frameworks (IDS)
- Requires dynamic memory access to system binaries
- Works with obfuscated/stripped system binaries
- No malicious functionality - purely for legitimate iMessage integration

## Debugging Tips
- Use `-check-compatibility` flag to verify offset correctness
- Sanity check should return error code -44023
- Binary crashes usually indicate wrong offsets
- Check system logs for detailed error information

## Future Work
- Improve automatic offset finding for macOS 15+
- Add better error handling for partial offset detection
- Research alternative approaches for newer macOS versions
- Consider app packaging for easier distribution