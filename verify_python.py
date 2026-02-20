#!/usr/bin/env python3
"""
Python Installation Verification Script
Checks if Python and required modules are properly installed
"""

import sys
import os

def check_python_version():
    """Check Python version"""
    print("\n" + "="*70)
    print("PYTHON INSTALLATION VERIFICATION")
    print("="*70)
    
    version = sys.version_info
    print(f"\n✓ Python Version: {version.major}.{version.minor}.{version.micro}")
    print(f"✓ Executable: {sys.executable}")
    print(f"✓ Platform: {sys.platform}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("⚠️  WARNING: Python 3.8+ recommended (found {}.{})".format(version.major, version.minor))
        return False
    return True

def check_standard_library():
    """Check if standard library modules are accessible"""
    print("\n" + "-"*70)
    print("STANDARD LIBRARY CHECK")
    print("-"*70)
    
    standard_modules = [
        'socket', 'ssl', 'json', 'os', 'sys', 'datetime', 
        'collections', 'traceback', 'logging', 'tempfile'
    ]
    
    all_ok = True
    for module_name in standard_modules:
        try:
            __import__(module_name)
            print(f"✓ {module_name:20s} - OK")
        except ImportError as e:
            print(f"✗ {module_name:20s} - MISSING: {e}")
            all_ok = False
    
    return all_ok

def check_azure_packages():
    """Check if Azure packages are installed"""
    print("\n" + "-"*70)
    print("AZURE SDK PACKAGES CHECK")
    print("-"*70)
    
    required_packages = [
        ('azure.identity', 'azure-identity'),
        ('azure.mgmt.resource', 'azure-mgmt-resource'),
        ('azure.mgmt.compute', 'azure-mgmt-compute'),
        ('azure.mgmt.network', 'azure-mgmt-network'),
        ('azure.mgmt.storage', 'azure-mgmt-storage'),
    ]
    
    all_ok = True
    for module_name, package_name in required_packages:
        try:
            __import__(module_name)
            print(f"✓ {package_name:30s} - Installed")
        except ImportError:
            print(f"✗ {package_name:30s} - NOT INSTALLED")
            all_ok = False
    
    return all_ok

def check_optional_packages():
    """Check if optional packages are installed"""
    print("\n" + "-"*70)
    print("OPTIONAL PACKAGES CHECK")
    print("-"*70)
    
    optional_packages = [
        ('six', 'six (Python 2/3 compatibility)'),
        ('openpyxl', 'openpyxl (Excel support)'),
        ('git', 'GitPython (Git repo scanning)'),
        ('yaml', 'PyYAML (YAML parsing)'),
        ('requests', 'requests (HTTP)'),
    ]
    
    for module_name, description in optional_packages:
        try:
            __import__(module_name)
            print(f"✓ {description:40s} - Installed")
        except ImportError:
            print(f"⚠️  {description:40s} - Not installed (optional)")

def print_installation_command():
    """Print command to install missing packages"""
    print("\n" + "="*70)
    print("INSTALLATION COMMANDS")
    print("="*70)
    
    python_exe = sys.executable
    
    print(f"\nIf packages are missing, run:")
    print(f"\n  {python_exe} -m pip install --upgrade pip")
    print(f"  {python_exe} -m pip install -r requirements.txt")

def main():
    """Main verification process"""
    results = []
    
    # Check Python version
    results.append(("Python Version", check_python_version()))
    
    # Check standard library
    results.append(("Standard Library", check_standard_library()))
    
    # Check Azure packages
    results.append(("Azure SDK", check_azure_packages()))
    
    # Check optional packages
    check_optional_packages()
    
    # Print summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    all_passed = all(result[1] for result in results if result[0] != "Optional Packages")
    
    for check_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {check_name:25s}: {status}")
    
    if all_passed:
        print("\n✅ All checks passed! Python installation is ready.")
        print("\nYou can now run:")
        print(f"  {sys.executable} azure_discovery.py")
    else:
        print("\n⚠️  Some checks failed. See above for details.")
        print_installation_command()
    
    print("\n" + "="*70)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Verification cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Verification failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
