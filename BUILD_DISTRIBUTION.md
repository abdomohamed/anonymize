# Building and Distributing the Executable

This document explains how to build and distribute a standalone executable version of the PII Anonymization Tool that can be shared with users who cannot install Python or download packages.

## Overview

The project uses **PyInstaller** to bundle the Python application, all dependencies, and the spaCy model into a single executable file. Users can run this file without any Python installation or setup.

## Building the Executable

### Prerequisites

- Python 3.9 or higher
- UV package manager (install from https://astral.sh/uv)

### Build Steps

#### On Linux/macOS:

```bash
./build.sh
```

#### On Windows:

```powershell
.\build.ps1
```

### What the Build Script Does

1. Verifies Python and UV are installed
2. Installs all project dependencies (including PyInstaller)
3. Downloads and installs the spaCy English model
4. Cleans previous build artifacts
5. Runs PyInstaller with the custom spec file
6. Creates a standalone executable in the `dist/` directory

### Build Output

After successful build, you'll find:
- **Linux/macOS**: `dist/anonymize` (single binary file)
- **Windows**: `dist/anonymize.exe` (single executable file)

Expected size: ~200-400 MB (includes Python runtime, all dependencies, and spaCy model)

## Distribution

### Sharing the Executable

1. Locate the built executable in the `dist/` directory
2. Share this single file with your users via:
   - File sharing service (Google Drive, Dropbox, OneDrive, etc.)
   - Internal company network/portal
   - USB drive
   - Email (if size permits)

3. Users can run it directly without any installation!

### Platform Requirements

⚠️ **Important**: The executable is platform-specific!

- Build on **Linux** → Works on Linux
- Build on **macOS** → Works on macOS  
- Build on **Windows** → Works on Windows

To support multiple platforms, you'll need to build on each platform separately.

## Using the Executable

Once the user has the executable, they can use it immediately:

### Linux/macOS:
```bash
# Make executable (first time only)
chmod +x anonymize

# Run it
./anonymize input.txt -o output.txt
```

### Windows:
```powershell
# Run it directly
.\anonymize.exe input.txt -o output.txt
```

### Full Usage Examples:

```bash
# Basic anonymization
./anonymize document.txt -o anonymized.txt

# Use specific strategy
./anonymize document.txt --strategy mask -o output.txt

# Process directory
./anonymize input_folder/ --dir -o output_folder/

# Show help
./anonymize --help
```

## Advantages of This Approach

✅ **No Python installation required** - Users don't need Python
✅ **No dependency downloads** - All packages are bundled
✅ **Works on secured systems** - No internet connection needed to run
✅ **Simple distribution** - Single file to share
✅ **Consistent environment** - Same versions everywhere

## Disadvantages to Consider

⚠️ **Large file size** - Executable is 200-400 MB
⚠️ **Platform-specific** - Must build separately for each OS
⚠️ **Slower startup** - First run extracts files to temp directory
⚠️ **Updates require rebuild** - Bug fixes need new executable

## Testing the Executable

Before distributing, test the executable:

```bash
# Test basic functionality
./dist/anonymize examples/sample_input.txt -o test_output.txt

# Verify output
cat test_output.txt

# Test with different strategies
./dist/anonymize examples/sample_input.txt --strategy hash -o test_hash.txt
```

## Troubleshooting Build Issues

### Issue: "Module not found" errors
**Solution**: The spec file may be missing dependencies. Add them to `hiddenimports` in `anonymize.spec`

### Issue: "spaCy model not found"
**Solution**: Make sure the spaCy model is installed before building:
```bash
uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
```

### Issue: Build fails with memory error
**Solution**: PyInstaller needs substantial RAM. Close other applications or use a machine with more memory.

### Issue: Antivirus blocks the executable
**Solution**: This is common with PyInstaller executables. Users may need to:
- Add an exception in their antivirus
- Request IT to whitelist the file
- Code-sign the executable (requires certificate)

## Advanced: Code Signing (Optional)

For corporate environments, you may want to code-sign the executable:

### Windows:
```powershell
# Using signtool (requires certificate)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com dist\anonymize.exe
```

### macOS:
```bash
# Using codesign (requires Apple Developer certificate)
codesign --sign "Developer ID Application: Your Name" dist/anonymize
```

This helps avoid antivirus/security warnings.

## Alternative: Docker Container

If the executable approach doesn't work, consider using Docker instead:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e .
RUN python -m spacy download en_core_web_sm
ENTRYPOINT ["python", "-m", "src.cli"]
```

Users with Docker can run: `docker run anonymize-tool input.txt -o output.txt`

## Support

If users encounter issues running the executable:
1. Verify they're using the correct version for their OS
2. Check antivirus/security software isn't blocking it
3. Ensure they have execute permissions (Linux/macOS)
4. Try running from command line to see error messages
