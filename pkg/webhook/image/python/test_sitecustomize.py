#!/usr/bin/env python3
"""
Tests for sitecustomize.py

Run it with:

cd <path to>/beyla/pkg/webhook/image/python
python3 -m pytest test_sitecustomize.py -v
"""

import unittest
import sys
import os
from unittest.mock import patch, mock_open, MagicMock
from io import StringIO
from pathlib import Path

# Add the current directory to sys.path to find sitecustomize
test_dir = Path(__file__).parent
if str(test_dir) not in sys.path:
    sys.path.insert(0, str(test_dir))

# Mock the inject call to prevent auto-execution on import
import sitecustomize
# Replace the inject function to prevent it from running
sitecustomize.inject = lambda: None


class TestParseDependencyLine(unittest.TestCase):
    """Test the parse_dependency_line function."""
    
    def test_valid_line_with_tilde(self):
        result = sitecustomize.parse_dependency_line('opentelemetry-api ~=1.11')
        self.assertEqual(result, ('opentelemetry-api', '~=1.11'))
    
    def test_valid_line_with_gte(self):
        result = sitecustomize.parse_dependency_line('requests >=2.28.0')
        self.assertEqual(result, ('requests', '>=2.28.0'))
    
    def test_valid_line_with_exact_version(self):
        result = sitecustomize.parse_dependency_line('flask ==2.0.1')
        self.assertEqual(result, ('flask', '==2.0.1'))
    
    def test_empty_line(self):
        result = sitecustomize.parse_dependency_line('')
        self.assertIsNone(result)
    
    def test_whitespace_only(self):
        result = sitecustomize.parse_dependency_line('   ')
        self.assertIsNone(result)
    
    def test_package_with_underscores(self):
        result = sitecustomize.parse_dependency_line('my_package >=1.0.0')
        self.assertEqual(result, ('my_package', '>=1.0.0'))
    
    def test_package_with_dots(self):
        result = sitecustomize.parse_dependency_line('my.package >=1.0.0')
        self.assertEqual(result, ('my.package', '>=1.0.0'))


class TestNormalizePackageName(unittest.TestCase):
    """Test the normalize_package_name function."""
    
    def test_with_underscores(self):
        self.assertEqual(sitecustomize.normalize_package_name('my_package'), 'my-package')
    
    def test_with_dots(self):
        self.assertEqual(sitecustomize.normalize_package_name('my.package'), 'my-package')
    
    def test_already_normalized(self):
        self.assertEqual(sitecustomize.normalize_package_name('my-package'), 'my-package')
    
    def test_uppercase(self):
        self.assertEqual(sitecustomize.normalize_package_name('MyPackage'), 'mypackage')
    
    def test_mixed_separators(self):
        self.assertEqual(sitecustomize.normalize_package_name('My_Package.Name'), 'my-package-name')
    
    def test_multiple_separators(self):
        self.assertEqual(sitecustomize.normalize_package_name('my___package'), 'my-package')


class TestCheckPackageVersion(unittest.TestCase):
    """Test the check_package_version function."""
    
    @patch('importlib.metadata.version')
    def test_compatible_version(self, mock_version):
        mock_version.return_value = '1.15.0'
        is_installed, is_compatible, installed_ver, error_msg = \
            sitecustomize.check_package_version('opentelemetry-api', '~=1.11')
        
        self.assertTrue(is_installed)
        self.assertTrue(is_compatible)
        self.assertEqual(installed_ver, '1.15.0')
        self.assertIsNone(error_msg)
    
    @patch('importlib.metadata.version')
    def test_incompatible_version(self, mock_version):
        mock_version.return_value = '2.0.0'
        is_installed, is_compatible, installed_ver, error_msg = \
            sitecustomize.check_package_version('opentelemetry-api', '~=1.11')
        
        self.assertTrue(is_installed)
        self.assertFalse(is_compatible)
        self.assertEqual(installed_ver, '2.0.0')
        self.assertIn('does not satisfy', error_msg)
    
    @patch('importlib.metadata.version')
    def test_package_not_found(self, mock_version):
        from importlib.metadata import PackageNotFoundError
        mock_version.side_effect = PackageNotFoundError('test-package')
        
        is_installed, is_compatible, installed_ver, error_msg = \
            sitecustomize.check_package_version('test-package', '>=1.0')
        
        self.assertFalse(is_installed)
        self.assertFalse(is_compatible)
        self.assertIsNone(installed_ver)
        self.assertEqual(error_msg, 'Package not installed')
    
    @patch('importlib.metadata.version')
    def test_exact_version_match(self, mock_version):
        mock_version.return_value = '2.28.0'
        is_installed, is_compatible, installed_ver, error_msg = \
            sitecustomize.check_package_version('requests', '==2.28.0')
        
        self.assertTrue(is_installed)
        self.assertTrue(is_compatible)
        self.assertEqual(installed_ver, '2.28.0')
        self.assertIsNone(error_msg)
    
    @patch('importlib.metadata.version')
    def test_greater_than_or_equal(self, mock_version):
        mock_version.return_value = '3.0.0'
        is_installed, is_compatible, installed_ver, error_msg = \
            sitecustomize.check_package_version('package', '>=2.0.0')
        
        self.assertTrue(is_installed)
        self.assertTrue(is_compatible)


class TestCheckAllDependencies(unittest.TestCase):
    """Test the check_all_dependencies function."""
    
    @patch('sitecustomize.check_package_version')
    def test_all_compatible(self, mock_check):
        mock_check.return_value = (True, True, '1.0.0', None)
        
        lines = ['package1 ~=1.0', 'package2 >=2.0']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        self.assertEqual(total, 2)
        self.assertEqual(len(not_installed), 0)
        self.assertEqual(len(conflicts), 0)
        self.assertEqual(len(compatible), 2)
        self.assertEqual(len(errors), 0)
    
    @patch('sitecustomize.check_package_version')
    def test_with_conflicts(self, mock_check):
        mock_check.return_value = (True, False, '2.0.0', 'Version mismatch')
        
        lines = ['package1 ~=1.0']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        self.assertEqual(total, 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(len(compatible), 0)
        self.assertEqual(conflicts[0][0], 'package1')
    
    @patch('sitecustomize.check_package_version')
    def test_with_not_installed(self, mock_check):
        mock_check.return_value = (False, False, None, 'Package not installed')
        
        lines = ['missing-package >=1.0']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        self.assertEqual(total, 1)
        self.assertEqual(len(not_installed), 1)
        self.assertEqual(not_installed[0][0], 'missing-package')
    
    @patch('sitecustomize.check_package_version')
    def test_mixed_results(self, mock_check):
        # Set up different return values for different calls
        mock_check.side_effect = [
            (True, True, '1.0.0', None),  # compatible
            (False, False, None, 'Not installed'),  # not installed
            (True, False, '2.0.0', 'Conflict'),  # conflict
        ]
        
        lines = ['pkg1 ~=1.0', 'pkg2 >=2.0', 'pkg3 ==1.0']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        self.assertEqual(total, 3)
        self.assertEqual(len(compatible), 1)
        self.assertEqual(len(not_installed), 1)
        self.assertEqual(len(conflicts), 1)
    
    def test_empty_lines(self):
        lines = ['', '  ', '\n']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        self.assertEqual(total, 0)
    
    @patch('sitecustomize.check_package_version')
    def test_pip_ignored(self, mock_check):
        mock_check.return_value = (True, True, '23.0', None)
        
        lines = ['pip >=20.0', 'other-package >=1.0']
        total, not_installed, conflicts, compatible, errors = \
            sitecustomize.check_all_dependencies(lines)
        
        # pip should be counted in total but not checked
        self.assertEqual(total, 2)
        # Only one call should be made (for other-package)
        self.assertEqual(mock_check.call_count, 1)


class TestCheckOtlpProto(unittest.TestCase):
    """Test the check_otlp_proto function."""
    
    @patch.dict(os.environ, {'OTEL_EXPORTER_OTLP_PROTOCOL': 'http/protobuf'})
    def test_http_protobuf_accepted(self):
        self.assertTrue(sitecustomize.check_otlp_proto())
    
    @patch.dict(os.environ, {'OTEL_EXPORTER_OTLP_PROTOCOL': 'http/json'})
    def test_http_json_accepted(self):
        self.assertTrue(sitecustomize.check_otlp_proto())
    
    @patch.dict(os.environ, {'OTEL_EXPORTER_OTLP_PROTOCOL': 'grpc'})
    def test_grpc_rejected(self):
        self.assertFalse(sitecustomize.check_otlp_proto())
    
    @patch.dict(os.environ, {'OTEL_EXPORTER_OTLP_PROTOCOL': ''})
    def test_empty_protocol_rejected(self):
        self.assertFalse(sitecustomize.check_otlp_proto())
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_protocol_rejected(self):
        # Ensure the key is not present
        if 'OTEL_EXPORTER_OTLP_PROTOCOL' in os.environ:
            del os.environ['OTEL_EXPORTER_OTLP_PROTOCOL']
        self.assertFalse(sitecustomize.check_otlp_proto())


class TestCheckPythonVersion(unittest.TestCase):
    """Test the check_python_version function."""
    
    def test_current_version_acceptable(self):
        # Should pass since tests require Python >= 3.9
        if sys.version_info >= (3, 9):
            self.assertTrue(sitecustomize.check_python_version())
    
    @patch.object(sys, 'version_info', (3, 8, 0, 'final', 0))
    def test_python_38_rejected(self):
        self.assertFalse(sitecustomize.check_python_version())
    
    @patch.object(sys, 'version_info', (3, 9, 0, 'final', 0))
    def test_python_39_accepted(self):
        self.assertTrue(sitecustomize.check_python_version())
    
    @patch.object(sys, 'version_info', (3, 10, 0, 'final', 0))
    def test_python_310_accepted(self):
        self.assertTrue(sitecustomize.check_python_version())
    
    @patch.object(sys, 'version_info', (2, 7, 18, 'final', 0))
    def test_python_27_rejected(self):
        self.assertFalse(sitecustomize.check_python_version())


class TestCheckPackageVersions(unittest.TestCase):
    """Test the check_package_versions function."""
    
    @patch('importlib.metadata.distributions')
    def test_single_version(self, mock_distributions):
        mock_dist = MagicMock()
        mock_dist.name = 'opentelemetry-api'
        mock_dist.version = '1.15.0'
        mock_dist.locate_file.return_value.parent = '/usr/lib/python3.9/site-packages'
        
        mock_distributions.return_value = [mock_dist]
        
        versions = sitecustomize.check_package_versions('opentelemetry-api')
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0][0], '1.15.0')
    
    @patch('importlib.metadata.distributions')
    def test_multiple_versions(self, mock_distributions):
        mock_dist1 = MagicMock()
        mock_dist1.name = 'requests'
        mock_dist1.version = '2.28.0'
        mock_dist1.locate_file.return_value.parent = '/usr/lib/python3.9/site-packages'
        
        mock_dist2 = MagicMock()
        mock_dist2.name = 'requests'
        mock_dist2.version = '2.29.0'
        mock_dist2.locate_file.return_value.parent = '/home/user/.local/lib/python3.9/site-packages'
        
        mock_distributions.return_value = [mock_dist1, mock_dist2]
        
        versions = sitecustomize.check_package_versions('requests')
        self.assertEqual(len(versions), 2)
    
    @patch('importlib.metadata.distributions')
    def test_package_not_found(self, mock_distributions):
        mock_dist = MagicMock()
        mock_dist.name = 'other-package'
        mock_distributions.return_value = [mock_dist]
        
        versions = sitecustomize.check_package_versions('missing-package')
        self.assertEqual(len(versions), 0)


if __name__ == '__main__':
    unittest.main()
