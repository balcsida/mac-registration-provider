# How to Verify Offsets for mac-registration-provider

## Understanding the Problem

The PR #53 for automatic offset finding doesn't work on macOS 15 Sequoia because:
1. The hex patterns used to find functions are too specific to older macOS versions
2. Only 2 out of 4 required offsets are found (missing NACInitAddress and NACSignAddress)
3. The code crashes with an index out of range error when offsets are missing

## Manual Offset Verification Methods

### Method 1: Using the Sanity Check
The most reliable way to verify if offsets are correct is the built-in sanity check in `nac/nac.go`:

```go
func SanityCheck() error {
    resp := int(C.nacInitProxy(nacInitAddr, nil, C.int(0), nil, nil, nil))
    if resp != -44023 {
        return fmt.Errorf("NACInit sanity check had unexpected response %d", resp)
    }
    return nil
}
```

This calls NACInit with null parameters and expects error code -44023. If you get a different error code or a crash, the offsets are wrong.

### Method 2: Binary Hash Verification
1. Get the SHA256 hash of your identityservicesd:
```bash
shasum -a 256 /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd
```

2. Check if this hash exists in `nac/offsets.go`

### Method 3: Symbol Resolution
Use `nm` to verify the reference symbol exists:
```bash
nm --defined-only --extern-only --arch=arm64e /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd | grep IDSProtoKeyTransparencyTrustedServiceReadFrom
```

### Method 4: Disassembly Verification (Advanced)
For finding new offsets, you need to:
1. Use a disassembler like Hopper, IDA Pro, or Ghidra
2. Find the NAC-related functions (NACInit, NACKeyEstablishment, NACSign)
3. Calculate their offsets relative to the reference symbol

## Testing on macOS 15 Sequoia

On macOS 15.6 (24G84), the automatic offset finder fails because:
- The binary structure has changed significantly
- Apple may have refactored or obfuscated the NAC functions
- The hex patterns need updating for newer macOS versions

## Current Status for macOS 15

As of now, macOS 15 Sequoia is **not supported** because:
1. No hardcoded offsets exist for macOS 15.x versions
2. The automatic offset finder cannot locate all required functions
3. Manual reverse engineering is needed to find the correct offsets

## How to Add Support for New macOS Versions

1. **Find the binary hash**:
   ```bash
   shasum -a 256 /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd
   ```

2. **Locate the offsets** using a disassembler:
   - Find `_IDSProtoKeyTransparencyTrustedServiceReadFrom` symbol
   - Locate NACInit, NACKeyEstablishment, and NACSign functions
   - Calculate their offsets from the base address

3. **Add to offsets.go**:
   ```go
   var offsets_15_6 = imdOffsetTuple{
       arm64: imdOffsets{
           ReferenceSymbol:            "IDSProtoKeyTransparencyTrustedServiceReadFrom",
           ReferenceAddress:           0xXXXXXX,
           NACInitAddress:             0xXXXXXX,
           NACKeyEstablishmentAddress: 0xXXXXXX,
           NACSignAddress:             0xXXXXXX,
       },
   }
   ```

4. **Test thoroughly**:
   - Run with `-check-compatibility` flag
   - Verify the sanity check passes
   - Test actual registration generation

## Reverse Engineering Attempt Results (macOS 15.6)

### What We Found
- **Binary hash**: `49d567b7bf44407e738e9917872671f615bad354090514d0d7d02ed577cfcac8`
- **Reference symbol**: Found at `0xd6588` (working)
- **NACKeyEstablishment**: Found at `0x65baa0` (confirmed working by PR #53)
- **NACInit**: Could not locate reliably 
- **NACSign**: Could not locate reliably

### Search Methods Attempted
1. **Pattern matching**: Updated hex patterns from PR #53 only found 2/4 required functions
2. **Symbol analysis**: No direct NAC function symbols in the binary
3. **Address estimation**: Based on relative positions from macOS 14.x versions
4. **Brute force testing**: Systematic search across reasonable address ranges
5. **Binary disassembly**: Limited by lack of debug symbols

### Technical Challenges
1. **Function obfuscation**: Apple may have renamed or restructured NAC functions in macOS 15
2. **Address space changes**: Significant layout changes from macOS 14.x to 15.x
3. **Stripped symbols**: No direct function names for NAC operations
4. **Testing complexity**: Each test requires full dynamic linking and could crash

### What Works vs. What Doesn't

#### ✅ Working
- Loading identityservicesd binary
- Finding reference symbol (`IDSProtoKeyTransparencyTrustedServiceReadFrom`)
- NACKeyEstablishment function (found by automated pattern matching)

#### ❌ Not Working  
- NACInit function (causes segmentation fault with estimated offsets)
- NACSign function (causes segmentation fault with estimated offsets)
- Automatic pattern matching for all required functions

### Next Steps for Complete Support

#### Option 1: Professional Reverse Engineering
- Use tools like Ghidra, IDA Pro, or Hopper
- Manually analyze the binary to find NAC function implementations
- Look for calling patterns and cross-references
- Estimated time: 4-8 hours for experienced reverse engineer

#### Option 2: Dynamic Analysis
- Use dtrace or similar tools to trace function calls
- Monitor what happens during actual iMessage registration
- Identify the correct function addresses through runtime analysis

#### Option 3: Pattern Improvement
- Analyze more macOS 15.x binaries to find common patterns
- Update the hex pattern matching in PR #53
- Create more flexible pattern matching that can handle minor variations

#### Option 4: Alternative Approach
- Research if Apple has provided new APIs for NAC operations
- Look for higher-level frameworks that might wrap NAC functionality
- Consider if the approach needs fundamental changes for macOS 15+

## Recommendations

1. **For users on macOS 15**: Currently no working solution - need to use macOS 14.x or wait for proper reverse engineering
2. **For developers**: 
   - The automatic offset finder (PR #53) needs significant improvements for macOS 15+
   - Consider implementing Option 1 or 2 above for reliable support
   - Add better error handling for partial offset detection
3. **For the PR**: 
   - Add error handling for missing offsets instead of crashing
   - Consider implementing fallback mechanisms
   - Update documentation about macOS 15 limitations

## Current Status
- **macOS 14.x and earlier**: ✅ Supported
- **macOS 15.x**: ❌ Not supported (requires manual reverse engineering)