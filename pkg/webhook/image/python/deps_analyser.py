#!/usr/bin/env python3
"""
Parse pipdeptree output and produce a sorted list of all individual dependencies.
"""

import re
from pathlib import Path


def parse_dependency_tree(filename):
    """
    Parse a pipdeptree output file and extract all unique package-version combinations.
    
    Args:
        filename: Path to the dependency tree file
        
    Returns:
        A sorted list of unique (package, version_requirement) tuples
    """
    dependencies = set()
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.rstrip()
            
            if not line:
                continue
            
            # Remove tree characters (├──, └──, │, etc.)
            cleaned = re.sub(r'^[│├└─\s]+', '', line)
            
            # Extract package name and version from lines like:
            # 1. "package-name==version" (top-level)
            # 2. "package-name [required: ..., installed: ...]" (dependency)
            
            if '==' in cleaned and '[' not in cleaned:
                # Top-level package: "opentelemetry-distro==0.60b1"
                parts = cleaned.split('==')
                package_name = parts[0].strip()
                version = '==' + parts[1].strip()
                dependencies.add((package_name, version))
            elif '[required:' in cleaned:
                # Dependency: "opentelemetry-api [required: ~=1.12, installed: 1.39.1]"
                package_name = cleaned.split('[')[0].strip()
                # Extract the required version
                required_match = re.search(r'\[required:\s*([^,]+),', cleaned)
                if required_match:
                    version_requirement = required_match.group(1).strip()
                    if version_requirement.lower() == 'any':
                        continue  # No version constraint, skip
                    dependencies.add((package_name, version_requirement))
    
    return sorted(dependencies)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse pipdeptree output and extract unique package-version combinations.'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Output only the dependency list without header'
    )
    
    args = parser.parse_args()
    
    # Parse the dependency tree file
    dep_file = Path(__file__).parent / 'dependency-tree.txt'
    
    if not dep_file.exists():
        print(f"Error: {dep_file} not found!")
        return
    
    dependencies = parse_dependency_tree(dep_file)
    
    if not args.quiet:
        print(f"Found {len(dependencies)} unique package-version combinations:\n")
    
    output_file = Path(__file__).parent / 'all-deps.txt'
    with open(output_file, 'w') as f:
        for package, version in dependencies:
            f.write(f"{package} {version}\n")
    
    if not args.quiet:
        print(f"Dependencies written to {output_file}")


if __name__ == '__main__':
    main()
