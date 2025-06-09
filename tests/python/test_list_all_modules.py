import unittest
import sys
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..')
sys.path.insert(0, PROJECT_ROOT)

from fusil.python.list_all_modules import ListAllModules


# --- The Test Suite Class ---

class TestListAllModules(unittest.TestCase):
    """
    Test suite for the ListAllModules class.

    This suite creates a temporary, fake package structure on the filesystem
    to provide a controlled environment for testing module discovery. This ensures
    that the tests are isolated, repeatable, and do not depend on the packages
    installed on the host machine.
    """

    def setUp(self):
        """
        Creates a temporary directory with a fake package structure and adds it to sys.path.
        """
        self.tmpdir = tempfile.mkdtemp(prefix="fusil_test_")
        self.pkg_dir = os.path.join(self.tmpdir, "pkgs")
        self.site_packages_dir = os.path.join(self.tmpdir, "site-packages")
        os.makedirs(self.pkg_dir)
        os.makedirs(self.site_packages_dir)

        # Create a mock logger
        self.mock_logger = MagicMock()

        # --- Create a fake package structure ---
        # main_pkg
        main_pkg_path = os.path.join(self.pkg_dir, "main_pkg")
        os.makedirs(main_pkg_path)
        open(os.path.join(main_pkg_path, "__init__.py"), "w").close()
        open(os.path.join(main_pkg_path, "module_a.py"), "w").close()
        open(os.path.join(main_pkg_path, "c_module.so"), "w").close()

        # main_pkg.sub_pkg
        sub_pkg_path = os.path.join(main_pkg_path, "sub_pkg")
        os.makedirs(sub_pkg_path)
        open(os.path.join(sub_pkg_path, "__init__.py"), "w").close()
        open(os.path.join(sub_pkg_path, "module_b.py"), "w").close()

        # blacklisted_pkg
        blacklisted_pkg_path = os.path.join(self.pkg_dir, "blacklisted_pkg")
        os.makedirs(blacklisted_pkg_path)
        open(os.path.join(blacklisted_pkg_path, "__init__.py"), "w").close()
        open(os.path.join(blacklisted_pkg_path, "secret_module.py"), "w").close()

        # A module that is not a package
        open(os.path.join(self.pkg_dir, "top_level_script.py"), "w").close()

        # site-packages pkg
        vendor_pkg_path = os.path.join(self.site_packages_dir, "vendor_pkg")
        os.makedirs(vendor_pkg_path)
        open(os.path.join(vendor_pkg_path, "__init__.py"), "w").close()
        open(os.path.join(vendor_pkg_path, "vendor_module.py"), "w").close()

        # Add the temporary directories to the Python path
        self.original_sys_path = sys.path[:]
        sys.path.insert(0, self.pkg_dir)
        sys.path.insert(0, self.site_packages_dir)

    def tearDown(self):
        """
        Removes the temporary directory and restores the original sys.path.
        """
        shutil.rmtree(self.tmpdir)
        sys.path = self.original_sys_path
        # Clear any cached imports from the temp directory
        modules_to_remove = [m for m in sys.modules if m.startswith(('main_pkg', 'vendor_pkg', 'blacklisted_pkg'))]
        for mod in modules_to_remove:
            del sys.modules[mod]

    # --- Tests for Private Helper Methods ---

    def test_is_valid_module(self):
        """Logic Test: Ensures the _is_valid_module filter works correctly."""
        # Setup ListAllModules instance
        lister = ListAllModules(self.mock_logger, only_c=False, site_package=True, blacklist=set(), skip_test=True)

        # Test 1: Standard Python module should be valid
        self.assertTrue(lister._is_valid_module('module_a', False, 'module_a.py', None, None))

        # Test 2: 'only_c' filter should reject Python modules
        lister.only_c = True
        self.assertFalse(lister._is_valid_module('module_a', False, 'module_a.py', None, None),
                         "Should be invalid when only_c is True")
        self.assertTrue(lister._is_valid_module('c_module', False, 'c_module.so', None, None),
                        "C module should be valid when only_c is True")

        # Test 3: 'site_package' filter should reject modules from site-packages
        lister.only_c = False
        lister.site_package = False
        self.assertFalse(lister._is_valid_module('vendor_module', False,
                                                 os.path.join(self.site_packages_dir, 'vendor_pkg', 'vendor_module.py'),
                                                 None, 'vendor_pkg'),
                         "Module in site-packages should be invalid when site_package is False")

        # Test 4: 'blacklist' filter should reject blacklisted modules
        lister.site_package = True
        lister.blacklist = {'blacklisted_pkg'}
        self.assertFalse(lister._is_valid_module('secret_module', False, None, None, 'blacklisted_pkg'),
                         "Module in a blacklisted package should be invalid")

    # --- Tests for Public Discovery Method ---

    def test_search_modules_finds_all(self):
        """Integration Test: Verifies that search_modules finds all valid modules in the mock filesystem."""
        lister = ListAllModules(self.mock_logger, only_c=False, site_package=True, blacklist=set(), skip_test=False)
        found_modules = lister.search_modules()

        expected = {
            # Standard packages
            'main_pkg',
            'main_pkg.module_a',
            'main_pkg.c_module',
            'main_pkg.sub_pkg',
            'main_pkg.sub_pkg.module_b',
            'blacklisted_pkg',
            'blacklisted_pkg.secret_module',
            # Site packages
            'vendor_pkg',
            'vendor_pkg.vendor_module',
        }
        # built-ins are also included by default
        expected.update(set(sys.builtin_module_names) - {'__main__'})

        # Use issubset because other system modules might be found
        self.assertTrue(expected.issubset(found_modules))

    def test_only_c_filter(self):
        """Integration Test: Verifies the 'only_c' filter."""
        lister = ListAllModules(self.mock_logger, only_c=True, site_package=True, blacklist=set(), skip_test=False)

        found_modules = lister.search_modules()

        self.assertIn('main_pkg.c_module', found_modules)
        self.assertNotIn('main_pkg.module_a', found_modules)
        self.assertNotIn('vendor_pkg.vendor_module', found_modules)

    def test_blacklist_filters_modules(self):
        """Integration Test: Verifies that the blacklist correctly filters modules and packages."""
        blacklist = {'blacklisted_pkg', 'main_pkg.module_a'}
        lister = ListAllModules(self.mock_logger, only_c=False, site_package=True, blacklist=blacklist, skip_test=False)
        found_modules = lister.search_modules()

        self.assertNotIn('blacklisted_pkg', found_modules)
        self.assertNotIn('blacklisted_pkg.secret_module', found_modules)
        self.assertNotIn('main_pkg.module_a', found_modules)
        # Ensure other modules are still present
        self.assertIn('main_pkg.c_module', found_modules)

    def test_blacklist_filters_submodules(self):
        """BUG TEST: Verifies that blacklisting a package also filters its submodules."""
        # This test is designed to fail if the bug exists where blacklisting
        # a package (e.g., 'main_pkg.sub_pkg') does not also remove its children
        # (e.g., 'main_pkg.sub_pkg.module_b').
        blacklist = {'main_pkg.sub_pkg'}
        lister = ListAllModules(self.mock_logger, only_c=False, site_package=True, blacklist=blacklist, skip_test=False)
        found_modules = lister.search_modules()

        self.assertNotIn('main_pkg.sub_pkg', found_modules)
        self.assertNotIn('main_pkg.sub_pkg.module_b', found_modules,
                         "Sub-module of a blacklisted package should not be included.")

    def test_no_site_packages_filter(self):
        """Integration Test: Verifies that modules from site-packages can be excluded."""
        lister = ListAllModules(self.mock_logger, only_c=False, site_package=False, blacklist=set(), skip_test=False)
        found_modules = lister.search_modules()

        self.assertNotIn('vendor_pkg', found_modules)
        self.assertNotIn('vendor_pkg.vendor_module', found_modules)
        # Ensure standard packages are still found
        self.assertIn('main_pkg', found_modules)


if __name__ == '__main__':
    unittest.main()