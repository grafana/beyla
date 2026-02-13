#!/usr/bin/env python3
"""
Tests for deps_analyser.py

Run it with:

cd <path to>/beyla/pkg/webhook/image/python
python3 -m pytest test_deps_analyser.py -v
"""

import unittest
import sys
import os
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from io import StringIO
import tempfile

# Add the current directory to sys.path to find deps_analyser
test_dir = Path(__file__).parent
if str(test_dir) not in sys.path:
    sys.path.insert(0, str(test_dir))

import deps_analyser


class TestParseDependencyTree(unittest.TestCase):
    """Test the parse_dependency_tree function."""
    
    def test_parse_top_level_package(self):
        """Test parsing a top-level package with exact version."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("opentelemetry-distro==0.60b1\n")
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], ('opentelemetry-distro', '==0.60b1'))
        finally:
            os.unlink(temp_file)
    
    def test_parse_dependency_with_required_version(self):
        """Test parsing a dependency line with [required:] format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]\n")
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], ('opentelemetry-api', '~=1.12'))
        finally:
            os.unlink(temp_file)
    
    def test_parse_nested_dependencies(self):
        """Test parsing nested dependencies with different tree characters."""
        content = """opentelemetry-distro==0.60b1
├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]
│   └── deprecated [required: >=1.2.6, installed: 1.2.14]
└── opentelemetry-sdk [required: ~=1.12, installed: 1.39.1]
    ├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]
    └── typing-extensions [required: >=3.7.4, installed: 4.12.2]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            # Check that we got all unique packages
            package_names = [pkg for pkg, ver in result]
            self.assertIn('opentelemetry-distro', package_names)
            self.assertIn('opentelemetry-api', package_names)
            self.assertIn('opentelemetry-sdk', package_names)
            self.assertIn('deprecated', package_names)
            self.assertIn('typing-extensions', package_names)
        finally:
            os.unlink(temp_file)
    
    def test_parse_empty_lines(self):
        """Test that empty lines are ignored."""
        content = """opentelemetry-distro==0.60b1

├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]

"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            self.assertEqual(len(result), 2)
        finally:
            os.unlink(temp_file)
    
    def test_parse_duplicate_packages(self):
        """Test that duplicate packages are deduplicated."""
        content = """opentelemetry-distro==0.60b1
├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]
└── opentelemetry-sdk [required: ~=1.12, installed: 1.39.1]
    └── opentelemetry-api [required: ~=1.12, installed: 1.39.1]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            # opentelemetry-api appears twice but should only be in result once
            package_names = [pkg for pkg, ver in result]
            self.assertEqual(package_names.count('opentelemetry-api'), 1)
        finally:
            os.unlink(temp_file)
    
    def test_parse_results_sorted(self):
        """Test that results are sorted alphabetically."""
        content = """zebra-package==1.0.0
alpha-package==2.0.0
beta-package==3.0.0
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            package_names = [pkg for pkg, ver in result]
            self.assertEqual(package_names, ['alpha-package', 'beta-package', 'zebra-package'])
        finally:
            os.unlink(temp_file)
    
    def test_parse_various_version_specifiers(self):
        """Test parsing various version specifier formats."""
        content = """├── package1 [required: ~=1.12, installed: 1.39.1]
├── package2 [required: >=2.0, installed: 2.5.0]
├── package3 [required: ==3.0.0, installed: 3.0.0]
├── package4 [required: !=1.0, installed: 2.0.0]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            versions = {pkg: ver for pkg, ver in result}
            self.assertEqual(versions['package1'], '~=1.12')
            self.assertEqual(versions['package2'], '>=2.0')
            self.assertEqual(versions['package3'], '==3.0.0')
            self.assertEqual(versions['package4'], '!=1.0')
        finally:
            os.unlink(temp_file)
    
    def test_parse_package_with_hyphens_underscores(self):
        """Test parsing package names with hyphens and underscores."""
        content = """my-package==1.0.0
another_package==2.0.0
├── mixed-package_name [required: >=1.0, installed: 1.5.0]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            package_names = [pkg for pkg, ver in result]
            self.assertIn('my-package', package_names)
            self.assertIn('another_package', package_names)
            self.assertIn('mixed-package_name', package_names)
        finally:
            os.unlink(temp_file)
    
    def test_ignore_lines_without_version_info(self):
        """Test that lines without version information are ignored."""
        content = """opentelemetry-distro==0.60b1
This is some random text
├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]
Another line without brackets
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            # Should only have the two valid lines
            self.assertEqual(len(result), 2)
        finally:
            os.unlink(temp_file)


class TestMain(unittest.TestCase):
    """Test the main function."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.original_parent = deps_analyser.Path(__file__).parent
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('deps_analyser.Path')
    @patch.object(sys, 'argv', ['deps_analyser.py', '--quiet'])
    def test_main_creates_output_file(self, mock_path_class):
        """Test that main creates the output file correctly."""
        # Create input file
        input_file = Path(self.test_dir) / 'dependency-tree.txt'
        output_file = Path(self.test_dir) / 'all-deps.txt'
        
        with open(input_file, 'w') as f:
            f.write("opentelemetry-distro==0.60b1\n")
            f.write("├── opentelemetry-api [required: ~=1.12, installed: 1.39.1]\n")
        
        # Mock Path to return our test directory
        mock_path_instance = MagicMock()
        mock_path_instance.parent = Path(self.test_dir)
        mock_path_class.return_value = mock_path_instance
        
        # Run main
        deps_analyser.main()
        
        # Check output file was created
        self.assertTrue(output_file.exists())
        
        # Check content
        with open(output_file, 'r') as f:
            lines = f.readlines()
        
        # Results will be alphabetically sorted
        self.assertEqual(len(lines), 2)
        self.assertIn('opentelemetry-api ~=1.12', lines[0])
        self.assertIn('opentelemetry-distro ==0.60b1', lines[1])
    
    @patch('deps_analyser.Path')
    @patch.object(sys, 'argv', ['deps_analyser.py'])
    @patch('builtins.print')
    def test_main_output_verbose(self, mock_print, mock_path_class):
        """Test that main prints verbose output when not in quiet mode."""
        # Create input file
        input_file = Path(self.test_dir) / 'dependency-tree.txt'
        
        with open(input_file, 'w') as f:
            f.write("opentelemetry-distro==0.60b1\n")
        
        # Mock Path to return our test directory
        mock_path_instance = MagicMock()
        mock_path_instance.parent = Path(self.test_dir)
        mock_path_class.return_value = mock_path_instance
        
        # Run main
        deps_analyser.main()
        
        # Check that print was called with verbose messages
        print_calls = [str(call) for call in mock_print.call_args_list]
        self.assertTrue(any('Found' in str(call) for call in print_calls))
        self.assertTrue(any('written to' in str(call) for call in print_calls))
    
    @patch('deps_analyser.Path')
    @patch.object(sys, 'argv', ['deps_analyser.py'])
    @patch('builtins.print')
    def test_main_file_not_found(self, mock_print, mock_path_class):
        """Test that main handles missing input file gracefully."""
        # Mock Path to return non-existent file
        mock_path_instance = MagicMock()
        mock_path_instance.parent = Path(self.test_dir)
        mock_path_class.return_value = mock_path_instance
        
        # Run main
        deps_analyser.main()
        
        # Check that error message was printed
        mock_print.assert_called()
        print_call = str(mock_print.call_args_list[0])
        self.assertIn('Error', print_call)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def test_empty_file(self):
        """Test parsing an empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("")
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_file)
    
    def test_whitespace_only_file(self):
        """Test parsing a file with only whitespace."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("   \n\n  \n")
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_file)
    
    def test_malformed_required_line(self):
        """Test that malformed [required:] lines are handled gracefully."""
        content = """├── package1 [required: ~=1.12, installed: 1.39.1]
├── package2 [missing-required-field]
├── package3 [required: >=2.0]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            # Only package1 should be parsed successfully
            # package2 has malformed format (no comma after required version)
            # package3 is missing the comma separator
            package_names = [pkg for pkg, ver in result]
            self.assertIn('package1', package_names)
        finally:
            os.unlink(temp_file)
    
    def test_package_with_dots_in_name(self):
        """Test parsing packages with dots in their names."""
        content = """zope.interface==5.4.0
├── setuptools [required: Any, installed: 65.5.0]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            f.flush()
            temp_file = f.name
        
        try:
            result = deps_analyser.parse_dependency_tree(temp_file)
            package_names = [pkg for pkg, ver in result]
            self.assertIn('zope.interface', package_names)
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()
