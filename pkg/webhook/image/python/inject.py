#!/usr/bin/env python
"""
Check for dependency conflicts in the current Python environment.
Reads a list of package dependencies and validates against installed versions.

Compatible with Python 2.7+ and Python 3, but requires Python >= 3.9 to run.
"""

from __future__ import print_function
import os
import sys
import re

verbose = os.environ.get('OTEL_INJECTOR_LOG_LEVEL') == 'debug'

def parse_dependency_line(line):
    """
    Parse a dependency line like 'opentelemetry-api ~=1.11'
    
    Args:
        line: String containing package name and version spec
        
    Returns:
        Tuple of (package_name, version_spec) or None if invalid
    """
    line = line.strip()
    if not line:
        return None
    
    # Match package name followed by version specifier
    # Package names can contain letters, numbers, hyphens, underscores, dots
    match = re.match(r'^([a-zA-Z0-9_.-]+)\s+(.+)$', line)
    if match:
        package_name = match.group(1)
        version_spec = match.group(2)
        return (package_name, version_spec)
    
    return None


def normalize_package_name(name):
    """
    Normalize package name according to PEP 503.
    Convert to lowercase and replace underscores/hyphens with hyphens.
    """
    return re.sub(r'[-_.]+', '-', name).lower()


def check_package_version(package_name, version_spec):
    """
    Check if an installed package version satisfies the version specification.
    
    Args:
        package_name: Name of the package to check
        version_spec: Version specification (e.g., '~=1.11', '>=2.0', '==1.39.1')
        
    Returns:
        Tuple of (is_installed, is_compatible, installed_version, error_message)
    """
    # Now we can safely import Python 3.9+ features
    try:
        from importlib.metadata import version, PackageNotFoundError
    except Exception as e:
        return (False, False, None, "Error checking package: {}".format(str(e)))

    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    from packaging.version import Version, InvalidVersion

    try:
        # Try to get the installed version
        # Try both the original name and normalized name
        installed_version_str = None
        try:
            installed_version_str = version(package_name)
        except PackageNotFoundError:
            # Try normalized name
            normalized = normalize_package_name(package_name)
            try:
                installed_version_str = version(normalized)
            except PackageNotFoundError:
                return (False, False, None, "Package not installed")
        
        # Parse the installed version
        try:
            installed_version = Version(installed_version_str)
        except InvalidVersion as e:
            return (True, False, installed_version_str, 
                    "Invalid version format: {}".format(str(e)))
        
        # Parse and check the version specification
        try:
            spec = SpecifierSet(version_spec)
            is_compatible = installed_version in spec
            
            if is_compatible:
                return (True, True, installed_version_str, None)
            else:
                return (True, False, installed_version_str,
                        "Version {} does not satisfy requirement {}".format(
                            installed_version_str, version_spec))
        except InvalidSpecifier as e:
            return (True, False, installed_version_str,
                    "Invalid version specifier '{}': {}".format(version_spec, str(e)))
    
    except Exception as e:
        return (False, False, None, "Error checking package: {}".format(str(e)))


def check_all_dependencies(lines):
    """
    Check all dependencies from input lines.
    
    Args:
        lines: List of strings containing dependency specifications
        
    Returns:
        Tuple of (total, not_installed, conflicts, compatible, errors)
    """
    # Track results
    total = 0
    not_installed = []
    conflicts = []
    compatible = []
    errors = []
    
    # Check each dependency
    for line in lines:
        parsed = parse_dependency_line(line)
        if not parsed:
            continue
        
        package_name, version_spec = parsed
        total += 1
        
        is_installed, is_compatible, installed_ver, error_msg = check_package_version(
            package_name, version_spec
        )
        
        if not is_installed:
            not_installed.append((package_name, version_spec, error_msg))
        elif not is_compatible:
            conflicts.append((package_name, version_spec, installed_ver, error_msg))
        elif error_msg:
            errors.append((package_name, version_spec, installed_ver, error_msg))
        else:
            compatible.append((package_name, version_spec, installed_ver))
    
    return (total, not_installed, conflicts, compatible, errors)


def verify_and_load():
    """Function to check dependency conflicts."""
    current_pkg_dir = os.path.dirname(__file__)
    input_file = os.path.join(current_pkg_dir, 'all-deps.txt')
        
    # Read dependencies from file or stdin
    if input_file:
        try:
            with open(input_file, 'r') as f:
                lines = f.readlines()
        except IOError as e:
            print("Error reading file: {}".format(e), file=sys.stderr)
            sys.path.remove(current_pkg_dir)
            return
    else:
        lines = sys.stdin.readlines()
    
    # Put ourselves last on the path to allow application 
    # dependencies to win even if we are compatible
    sys.path.remove(current_pkg_dir)
    sys.path.append(current_pkg_dir)

    # Check all dependencies
    total, not_installed, conflicts, compatible, errors = check_all_dependencies(lines)
    
    # Print results
    if verbose:
        print("=" * 70)
        print("Dependency Conflict Check Report")
        print("=" * 70)
        print("Python version: {}.{}.{}".format(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro
        ))
        print("Total dependencies checked: {}".format(total))
        print()
    
        # Show conflicts
        if conflicts:
            print("CONFLICTS FOUND ({})".format(len(conflicts)))
            print("-" * 70)
            for pkg, spec, installed, msg in conflicts:
                print("  {} {}".format(pkg, spec))
                print("    Installed: {}".format(installed))
                print("    Issue: {}".format(msg))
                print()
        else:
            print("No conflicts found!")
            print()
    
        # Show not installed packages
        if not_installed:
            print("NOT INSTALLED ({})".format(len(not_installed)))
            print("-" * 70)
            for pkg, spec, msg in not_installed:
                print("  {} {} - {}".format(pkg, spec, msg))
            print()
        
        # Show errors
        if errors:
            print("ERRORS ({})".format(len(errors)))
            print("-" * 70)
            for pkg, spec, installed, msg in errors:
                print("  {} {} (installed: {})".format(pkg, spec, installed))
                print("    Error: {}".format(msg))
                print()
    
        # Show compatible packages
        if compatible:
            print("COMPATIBLE ({})".format(len(compatible)))
            print("-" * 70)
            for pkg, spec, installed in compatible:
                print("  {} {} (installed: {})".format(pkg, spec, installed))
            print()
    
        # Summary
        print("=" * 70)
        print("Summary:")
        print("  Compatible: {}".format(len(compatible)))
        print("  Conflicts: {}".format(len(conflicts)))
        print("  Not installed: {}".format(len(not_installed)))
        print("  Errors: {}".format(len(errors)))
        print("=" * 70)
    
    # Exit with error code if conflicts found
    if not conflicts or errors:
        try:
            if verbose:
                print("Importing and initializing OpenTelemetry Python auto-instrumentation")
            from opentelemetry.instrumentation import auto_instrumentation
            auto_instrumentation.initialize()
        except Exception as e:
            print("Error installing OpenTelemetry auto-instrumentation: {}".format(e), file=sys.stderr)
            sys.path.remove(current_pkg_dir)
    else:
        sys.path.remove(current_pkg_dir)

def check_otlp_proto(): 
    """
    Python default export protocol uses gRPC, but the operator requirements.txt don't package
    the grpc exporter. We verify that the config supplied explicitly 'http/protobuf' or we 
    refuse to auto-instrument.
    
    Returns:
        True if OTLP protocol is acceptable, False otherwise
    """
    proto = os.environ.get('OTEL_EXPORTER_OTLP_PROTOCOL')
    if (proto is None) or (proto == 'grpc') or (proto == ''):
        print("gRPC export protocol not supported, use OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf for auto-instrumentation")
        return False
    return True

def check_python_version():
    """
    Check if Python version is >= 3.9.
    
    Returns:
        True if version is acceptable, False otherwise
    """
    if sys.version_info < (3, 9):
        print("Python version 3.9 or higher required for auto-instrumentation", file=sys.stderr)
        return False
    return True

def inject():
    if not check_python_version():
        return
    if not check_otlp_proto():
        return
    verify_and_load()

inject()
