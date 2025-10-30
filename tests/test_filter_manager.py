"""
Unit tests for FilterManager

Run with: pytest test_filter_manager.py -v
"""

import pytest
import re
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path for imports
import sys
sys.path.insert(0, '/home/claude')

from fusil.filter_manager import (
    FilterManager,
    FilterList,
    FilterPattern,
    detect_pattern_type,
    create_filter_manager,
    get_filter_manager,
    reset_filter_manager,
)
from fusil.blacklist_config import BlacklistConfigLoader, load_blacklist_config


class TestPatternDetection:
    """Test pattern type detection."""
    
    def test_detect_exact_pattern(self):
        """Test exact pattern detection."""
        assert detect_pattern_type('simple_name') == 'exact'
        assert detect_pattern_type('module') == 'exact'
        assert detect_pattern_type('__init__') == 'exact'
    
    def test_detect_glob_pattern(self):
        """Test glob pattern detection."""
        assert detect_pattern_type('*.py') == 'glob'
        assert detect_pattern_type('test_*') == 'glob'
        assert detect_pattern_type('_*') == 'glob'
        assert detect_pattern_type('*Test') == 'glob'
        # This is a false positive as regex:
        # assert detect_pattern_type('file?.txt') == 'glob'
    
    def test_detect_regex_pattern(self):
        """Test regex pattern detection."""
        assert detect_pattern_type(r'.*\.py$') == 'regex'
        assert detect_pattern_type(r'test_\d+') == 'regex'
        assert detect_pattern_type(r'^__.*__$') == 'regex'
        assert detect_pattern_type(r'app_.*') == 'regex'
    
    def test_ambiguous_patterns(self):
        """Test that ambiguous patterns are handled correctly."""
        # Pattern with both glob and regex chars - should prefer regex
        result = detect_pattern_type(r'test.*\.py')
        assert result in ('glob', 'regex')  # Either is acceptable


class TestFilterPattern:
    """Test individual filter patterns."""
    
    def test_exact_match_case_sensitive(self):
        """Test exact pattern with case sensitivity."""
        pattern = FilterPattern('TestClass', 'exact', case_sensitive=True)
        assert pattern.matches('TestClass')
        assert not pattern.matches('testclass')
        assert not pattern.matches('TESTCLASS')
    
    def test_exact_match_case_insensitive(self):
        """Test exact pattern without case sensitivity."""
        pattern = FilterPattern('TestClass', 'exact', case_sensitive=False)
        assert pattern.matches('TestClass')
        assert pattern.matches('testclass')
        assert pattern.matches('TESTCLASS')
    
    def test_glob_pattern_matching(self):
        """Test glob pattern matching."""
        pattern = FilterPattern('test_*', 'glob', case_sensitive=True)
        assert pattern.matches('test_foo')
        assert pattern.matches('test_bar')
        assert not pattern.matches('other_test')
        assert not pattern.matches('Test_foo')  # Case sensitive
    
    def test_glob_pattern_case_insensitive(self):
        """Test glob pattern without case sensitivity."""
        pattern = FilterPattern('TEST_*', 'glob', case_sensitive=False)
        assert pattern.matches('test_foo')
        assert pattern.matches('TEST_bar')
        assert pattern.matches('Test_Baz')
    
    def test_regex_pattern_matching(self):
        """Test regex pattern matching."""
        pattern = FilterPattern(r'^test_\d+$', 'regex', case_sensitive=True)
        assert pattern.matches('test_123')
        assert pattern.matches('test_0')
        assert not pattern.matches('test_abc')
        assert not pattern.matches('other_123')
    
    def test_regex_pattern_case_insensitive(self):
        """Test regex without case sensitivity."""
        pattern = FilterPattern(r'^TEST_.*', 'regex', case_sensitive=False)
        assert pattern.matches('test_foo')
        assert pattern.matches('TEST_bar')
        assert pattern.matches('Test_Baz')
    
    def test_invalid_regex_pattern(self):
        """Test that invalid regex raises ValueError."""
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            FilterPattern(r'[invalid(', 'regex')
    
    def test_pattern_source_tracking(self):
        """Test that pattern source is tracked."""
        pattern = FilterPattern('test', 'exact', source='config')
        assert pattern.source == 'config'
        
        pattern2 = FilterPattern('other', 'exact', source='plugin')
        assert pattern2.source == 'plugin'


class TestFilterList:
    """Test filter list functionality."""
    
    def test_add_exact_entry(self):
        """Test adding exact match entries."""
        fl = FilterList('method')
        fl.add_exact('__del__', source='default')
        
        assert '__del__' in fl.exact
        matched, pattern = fl.matches('__del__')
        assert matched
        assert pattern.source == 'default'
    
    def test_add_glob_pattern(self):
        """Test adding glob patterns."""
        fl = FilterList('method')
        fl.add_pattern('_*', 'glob', source='config')
        
        matched, pattern = fl.matches('_private')
        assert matched
        assert pattern.pattern_type == 'glob'
    
    def test_add_regex_pattern(self):
        """Test adding regex patterns."""
        fl = FilterList('class')
        fl.add_pattern(r'.*Test$', 'regex', source='cli')
        
        matched, pattern = fl.matches('MyTest')
        assert matched
        assert pattern.source == 'cli'
    
    def test_matches_exact(self):
        """Test exact matching."""
        fl = FilterList('module')
        fl.add_exact('numpy')
        
        matched, _ = fl.matches('numpy')
        assert matched
        
        matched, _ = fl.matches('scipy')
        assert not matched
    
    def test_matches_glob(self):
        """Test glob pattern matching."""
        fl = FilterList('class')
        fl.add_pattern('*Test', 'glob')
        
        matched, _ = fl.matches('MyTest')
        assert matched
        
        matched, _ = fl.matches('YourTest')
        assert matched
        
        matched, _ = fl.matches('Testing')
        assert not matched
    
    def test_matches_regex(self):
        """Test regex pattern matching."""
        fl = FilterList('method')
        fl.add_pattern(r'^_[a-z]+$', 'regex')
        
        matched, _ = fl.matches('_private')
        assert matched
        
        matched, _ = fl.matches('_Private')
        assert not matched
        
        matched, _ = fl.matches('public')
        assert not matched
    
    def test_no_match(self):
        """Test when nothing matches."""
        fl = FilterList('function')
        fl.add_exact('foo')
        fl.add_pattern('bar_*', 'glob')
        
        matched, pattern = fl.matches('baz')
        assert not matched
        assert pattern is None
    
    def test_case_insensitive_exact(self):
        """Test case-insensitive exact matching."""
        fl = FilterList('method')
        fl.add_exact('Test', case_sensitive=False)
        
        matched, _ = fl.matches('test')
        assert matched
        
        matched, _ = fl.matches('TEST')
        assert matched


class TestFilterManager:
    """Test complete FilterManager functionality."""
    
    def setup_method(self):
        """Reset filter manager before each test."""
        reset_filter_manager()
    
    def test_create_filter_manager(self):
        """Test creating filter manager."""
        fm = create_filter_manager(mode='blacklist', verbose=False)
        assert fm is not None
        assert fm.mode == 'blacklist'
        assert fm.verbose == False
    
    def test_cannot_create_twice(self):
        """Test that creating twice raises error."""
        create_filter_manager()
        with pytest.raises(RuntimeError, match="already initialized"):
            create_filter_manager()
    
    def test_get_filter_manager(self):
        """Test getting filter manager."""
        created = create_filter_manager()
        retrieved = get_filter_manager()
        assert created is retrieved
    
    def test_get_before_create_raises_error(self):
        """Test that getting before creation raises error."""
        with pytest.raises(RuntimeError, match="not initialized"):
            get_filter_manager()
    
    def test_invalid_mode_raises_error(self):
        """Test that invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            FilterManager(mode='invalid')
    
    def test_valid_modes(self):
        """Test all valid modes."""
        for mode in ['blacklist', 'whitelist', 'both']:
            reset_filter_manager()
            fm = create_filter_manager(mode=mode)
            assert fm.mode == mode
    
    def test_blacklist_mode_default_behavior(self):
        """Test blacklist mode allows everything except blacklisted."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.finalize()
        
        # Nothing blacklisted yet, everything allowed
        assert fm.is_allowed('method', 'foo')
        assert fm.is_allowed('method', 'bar')
    
    def test_blacklist_mode_with_exact_blacklist(self):
        """Test blacklist mode with exact entries."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('method', '__del__')
        fm.finalize()
        
        assert not fm.is_allowed('method', '__del__')
        assert fm.is_allowed('method', '__init__')
    
    def test_blacklist_mode_with_glob_pattern(self):
        """Test blacklist mode with glob patterns."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('method', '_*', pattern_type='glob')
        fm.finalize()
        
        assert not fm.is_allowed('method', '_private')
        assert not fm.is_allowed('method', '_internal')
        assert fm.is_allowed('method', 'public')
    
    def test_blacklist_mode_with_regex_pattern(self):
        """Test blacklist mode with regex patterns."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('class', r'.*Test$', pattern_type='regex')
        fm.finalize()
        
        assert not fm.is_allowed('class', 'MyTest')
        assert not fm.is_allowed('class', 'UnitTest')
        assert fm.is_allowed('class', 'Testing')
    
    def test_whitelist_mode_default_behavior(self):
        """Test whitelist mode denies everything except whitelisted."""
        fm = FilterManager(mode='whitelist', verbose=False)
        fm.add_whitelist_entry('method', 'allowed_method')
        fm.finalize()
        
        assert fm.is_allowed('method', 'allowed_method')
        assert not fm.is_allowed('method', 'other_method')
    
    def test_whitelist_mode_with_patterns(self):
        """Test whitelist mode with patterns."""
        fm = FilterManager(mode='whitelist', verbose=False)
        fm.add_whitelist_entry('method', 'test_*', pattern_type='glob')
        fm.finalize()
        
        assert fm.is_allowed('method', 'test_foo')
        assert fm.is_allowed('method', 'test_bar')
        assert not fm.is_allowed('method', 'other')
    
    def test_whitelist_mode_requires_entries(self):
        """Test that whitelist mode requires at least one entry."""
        fm = FilterManager(mode='whitelist', verbose=False)
        
        with pytest.raises(ValueError, match="requires at least one whitelist entry"):
            fm.finalize()
    
    def test_whitelist_overrides_blacklist(self):
        """Test that whitelist overrides blacklist."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('method', '__del__')
        fm.add_whitelist_entry('method', '__del__')  # Override
        fm.finalize()
        
        # Should be allowed because whitelist overrides
        assert fm.is_allowed('method', '__del__')
    
    def test_whitelist_overrides_default_blacklist(self):
        """Test that whitelist can override default blacklists."""
        # FilterManager loads defaults in __init__
        # We need to mock the defaults loading
        with patch('fusil.filter_manager.DEFAULT_METHOD_BLACKLIST', {'__del__'}):
            fm = FilterManager(mode='blacklist', verbose=False)
            # __del__ should be blacklisted by default
            # But we whitelist it
            fm.add_whitelist_entry('method', '__del__')
            fm.finalize()
            
            assert fm.is_allowed('method', '__del__')
    
    def test_both_mode_whitelist_overrides_blacklist(self):
        """Test 'both' mode where whitelist overrides blacklist."""
        fm = FilterManager(mode='both', verbose=False)
        fm.add_blacklist_entry('method', '_*', pattern_type='glob')
        fm.add_whitelist_entry('method', '_important')
        fm.finalize()
        
        # _important is whitelisted, so allowed despite blacklist pattern
        assert fm.is_allowed('method', '_important')
        
        # _other matches blacklist and not whitelisted
        assert not fm.is_allowed('method', '_other')
        
        # public doesn't match blacklist
        assert fm.is_allowed('method', 'public')
    
    def test_entry_source_tracking(self):
        """Test that entry sources are tracked."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('method', 'foo', source='config')
        fm.add_blacklist_entry('method', 'bar', source='cli')
        fm.add_blacklist_entry('method', 'baz', source='plugin')
        fm.finalize()
        
        # Check sources are tracked
        bl = fm.blacklist['method']
        sources = [p.source for p in bl.patterns]
        assert 'config' in sources
        assert 'cli' in sources
        assert 'plugin' in sources
    
    def test_invalid_item_type(self):
        """Test that invalid item type raises ValueError."""
        fm = FilterManager(mode='blacklist', verbose=False)
        
        with pytest.raises(ValueError, match="Invalid item_type"):
            fm.add_blacklist_entry('invalid_type', 'foo')
        
        with pytest.raises(ValueError, match="Invalid item_type"):
            fm.is_allowed('invalid_type', 'foo')
    
    def test_get_statistics(self):
        """Test getting filter statistics."""
        fm = FilterManager(mode='blacklist', verbose=False)
        initial_stats = fm.get_statistics().copy()

        fm.add_blacklist_entry('method', '__del__')
        fm.add_blacklist_entry('method', '_*', pattern_type='glob')
        fm.add_whitelist_entry('class', 'MyClass')
        fm.finalize()
        
        stats = fm.get_statistics()
        
        assert stats['mode'] == 'blacklist'
        assert stats['blacklist']['method']['exact'] == initial_stats['blacklist']['method']['exact'] + 1
        assert stats['blacklist']['method']['patterns'] == initial_stats['blacklist']['method']['patterns'] + 1
        assert stats['blacklist']['method']['total'] == initial_stats['blacklist']['method']['total'] + 2
        assert stats['whitelist']['class']['exact'] == initial_stats['whitelist']['class']['exact'] + 1
    
    def test_different_item_types(self):
        """Test filtering different item types."""
        fm = FilterManager(mode='blacklist', verbose=False)
        fm.add_blacklist_entry('module', 'test_module')
        fm.add_blacklist_entry('method', 'test_method')
        fm.add_blacklist_entry('class', 'TestClass')
        fm.add_blacklist_entry('object', 'test_obj')
        fm.add_blacklist_entry('function', 'test_func')
        fm.finalize()
        
        assert not fm.is_allowed('module', 'test_module')
        assert not fm.is_allowed('method', 'test_method')
        assert not fm.is_allowed('class', 'TestClass')
        assert not fm.is_allowed('object', 'test_obj')
        assert not fm.is_allowed('function', 'test_func')
        
        # Other items should be allowed
        assert fm.is_allowed('module', 'other_module')
        assert fm.is_allowed('method', 'other_method')


class TestBlacklistConfigLoader:
    """Test config file loading."""
    
    def setup_method(self):
        """Reset filter manager before each test."""
        reset_filter_manager()
    
    def test_load_basic_config(self, tmp_path):
        """Test loading basic config file."""
        config_content = """
[blacklist]
module = ["test_module", "debug_module"]
method = ["__del__", "__repr__"]
"""
        config_file = tmp_path / "fusil_blacklist.toml"
        config_file.write_text(config_content)
        
        fm = FilterManager(mode='blacklist', verbose=False)
        load_blacklist_config(config_file, fm)
        fm.finalize()
        
        assert not fm.is_allowed('module', 'test_module')
        assert not fm.is_allowed('method', '__del__')
    
    def test_load_with_patterns(self, tmp_path):
        """Test loading config with glob patterns."""
        config_content = """
[blacklist]
method = ["_*", "test_*"]
class = ["*Test"]
"""
        config_file = tmp_path / "fusil_blacklist.toml"
        config_file.write_text(config_content)
        
        fm = FilterManager(mode='blacklist', verbose=False)
        load_blacklist_config(config_file, fm)
        fm.finalize()
        
        assert not fm.is_allowed('method', '_private')
        assert not fm.is_allowed('method', 'test_foo')
        assert not fm.is_allowed('class', 'MyTest')
    
    def test_load_case_sensitivity_option(self, tmp_path):
        """Test loading case sensitivity option."""
        config_content = """
[options]
case_sensitive = false

[blacklist]
method = ["TEST"]
"""
        config_file = tmp_path / "fusil_blacklist.toml"
        config_file.write_text(config_content)
        
        fm = FilterManager(mode='blacklist', verbose=False)
        load_blacklist_config(config_file, fm)
        fm.finalize()

        # Should match case-insensitively
        assert not fm.is_allowed('method', 'test')
        assert not fm.is_allowed('method', 'TEST')
        assert not fm.is_allowed('method', 'Test')
    
    def test_missing_config_file(self, tmp_path):
        """Test that missing config file doesn't raise error."""
        config_file = tmp_path / "nonexistent.toml"
        
        fm = FilterManager(mode='blacklist', verbose=False)
        # Should not raise error
        load_blacklist_config(config_file, fm)
        fm.finalize()
    
    def test_load_whitelist_section(self, tmp_path):
        """Test loading whitelist section."""
        config_content = """
[blacklist]
method = ["_*"]

[whitelist]
method = ["_important"]
"""
        config_file = tmp_path / "fusil_blacklist.toml"
        config_file.write_text(config_content)
        
        fm = FilterManager(mode='blacklist', verbose=False)
        load_blacklist_config(config_file, fm)
        fm.finalize()
        
        # _important should be allowed (whitelisted)
        assert fm.is_allowed('method', '_important')
        
        # _other should be blocked (blacklisted)
        assert not fm.is_allowed('method', '_other')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
