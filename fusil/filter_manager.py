"""
Filter Manager for Fusil

Provides blacklist/whitelist filtering for modules, methods, classes, objects, and functions.
Supports exact matches, glob patterns, and regex patterns.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from fusil.python.blacklists import (
    DEFAULT_MODULE_BLACKLIST,
    DEFAULT_METHOD_BLACKLIST,
    DEFAULT_OBJECT_BLACKLIST,
    DEFAULT_BLACKLIST,
)

def detect_pattern_type(pattern: str) -> str:
    """
    Auto-detect pattern type using speculative compilation.
    
    Strategy:
    1. Try to compile as regex
    2. If successful and contains regex-specific chars, use regex
    3. Otherwise, treat as glob (more user-friendly for simple wildcards)
    4. If both fail, error out
    
    Args:
        pattern: The pattern string to analyze
        
    Returns:
        'exact', 'glob', or 'regex'
    """
    # Check if it's a simple literal (no special chars at all)
    has_glob_chars = '*' in pattern or '?' in pattern
    has_regex_chars = bool(re.search(r'[.^$+{}\[\]|()\\]', pattern))
    
    if not has_glob_chars and not has_regex_chars:
        return 'exact'
    
    # If it has glob chars but no regex-specific chars, treat as glob
    if has_glob_chars and not has_regex_chars:
        return 'glob'
    
    # Has regex-specific chars - try to compile as regex
    if has_regex_chars:
        try:
            re.compile(pattern)
            return 'regex'
        except re.error:
            # Regex compilation failed, try as glob and raise if it fails
            re.compile(fnmatch.translate(pattern))
    
    # Default to glob for wildcards
    return 'glob'


@dataclass
class FilterPattern:
    """Represents a single filter pattern."""
    
    pattern: str
    pattern_type: str  # 'exact', 'glob', 'regex'
    case_sensitive: bool = True
    source: str = 'default'  # 'default', 'config', 'cli', 'plugin'
    _compiled: Any = field(init=False, repr=False, default=None)
    
    def __post_init__(self):
        """Compile pattern based on type."""
        if self.pattern_type == 'glob':
            # Convert glob to regex
            regex_pattern = fnmatch.translate(self.pattern)
            flags = 0 if self.case_sensitive else re.IGNORECASE
            try:
                self._compiled = re.compile(regex_pattern, flags)
            except re.error as e:
                raise ValueError(
                    f"Invalid glob pattern '{self.pattern}': {e}"
                )
        
        elif self.pattern_type == 'regex':
            flags = 0 if self.case_sensitive else re.IGNORECASE
            try:
                self._compiled = re.compile(self.pattern, flags)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex pattern '{self.pattern}': {e}"
                )
        
        # exact match doesn't need compilation
    
    def matches(self, text: str) -> bool:
        """Check if text matches this pattern."""
        if self.pattern_type == 'exact':
            if self.case_sensitive:
                return text == self.pattern
            else:
                return text.lower() == self.pattern.lower()
        
        else:  # glob or regex (both compiled to regex)
            return bool(self._compiled.fullmatch(text))


class FilterList:
    """Manages filters for a specific item type (module, method, etc.)."""
    
    def __init__(self, item_type: str):
        self.item_type = item_type
        self.exact: set[str] = set()
        self.exact_insensitive: set[str] = set()  # Lowercase versions
        self.patterns: list[FilterPattern] = []
    
    def add_exact(self, name: str, source: str = 'default', 
                  case_sensitive: bool = True):
        """Add exact match filter."""
        if case_sensitive:
            self.exact.add(name)
        else:
            self.exact_insensitive.add(name.lower())
        
        # Also store as pattern for source tracking
        pattern = FilterPattern(
            pattern=name,
            pattern_type='exact',
            case_sensitive=case_sensitive,
            source=source
        )
        self.patterns.append(pattern)
    
    def add_pattern(self, pattern: str, pattern_type: str, 
                   case_sensitive: bool = True, source: str = 'default'):
        """Add pattern filter (glob or regex)."""
        if pattern_type not in ('glob', 'regex'):
            raise ValueError(
                f"Invalid pattern_type: {pattern_type}. Must be 'glob' or 'regex'"
            )

        filter_pattern = FilterPattern(
            pattern=pattern,
            pattern_type=pattern_type,
            case_sensitive=case_sensitive,
            source=source
        )
        self.patterns.append(filter_pattern)
    
    def matches(self, name: str) -> tuple[bool, FilterPattern | None]:
        """
        Check if name matches any filter.
        
        Returns:
            (matched, pattern_obj) - pattern_obj is None if no match
        """
        # Fast path: check exact matches first (O(1))
        if name in self.exact:
            # Find the pattern object for source tracking
            for pattern in self.patterns:
                if pattern.pattern_type == 'exact' and pattern.matches(name):
                    return True, pattern
            return True, None
        
        # Check case-insensitive exact matches
        if name.lower() in self.exact_insensitive:
            for pattern in self.patterns:
                if pattern.pattern_type == 'exact' and pattern.matches(name):
                    return True, pattern
        
        # Check patterns (O(n) where n = number of patterns)
        for pattern in self.patterns:
            if pattern.pattern_type == 'exact':
                continue  # Already checked above
            
            if pattern.matches(name):
                return True, pattern
        
        return False, None


class FilterManager:
    """
    Central manager for blacklist/whitelist filtering.
    
    Modes:
    - 'blacklist': Allow everything except blacklisted items
    - 'whitelist': Deny everything except whitelisted items
    - 'both': Whitelist overrides blacklist, then apply blacklist rules
    """
    
    # Item types we support
    ITEM_TYPES = ['module', 'method', 'class', 'object', 'function']
    VALID_MODES = ['blacklist', 'whitelist', 'both']
    
    def __init__(self, mode: str = 'blacklist', verbose: bool = False):
        if mode not in self.VALID_MODES:
            raise ValueError(
                f"Invalid mode: {mode}. Must be one of {self.VALID_MODES}"
            )
        
        self.mode = mode
        self.verbose = verbose

        # Separate blacklist and whitelist storage
        self.blacklist: dict[str, FilterList] = {
            item_type: FilterList(item_type) for item_type in self.ITEM_TYPES
        }
        self.whitelist: dict[str, FilterList] = {
            item_type: FilterList(item_type) for item_type in self.ITEM_TYPES
        }
        
        self._initialized = False
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default blacklist entries (migrated from blacklists.py)."""

        for module in DEFAULT_MODULE_BLACKLIST:
            self.add_blacklist_entry('module', module, source='default')
        
        for method in DEFAULT_METHOD_BLACKLIST:
            self.add_blacklist_entry('method', method, source='default')
        
        for obj in DEFAULT_OBJECT_BLACKLIST:
            self.add_blacklist_entry('object', obj, source='default')
        
        # DEFAULT_BLACKLIST contains functions and classes
        for item in DEFAULT_BLACKLIST:
            self.add_blacklist_entry('function', item, source='default')
            self.add_blacklist_entry('class', item, source='default')
    
    def add_blacklist_entry(self, item_type: str, name: str, 
                           pattern_type: str = 'exact',
                           case_sensitive: bool = True,
                           source: str = 'user'):
        """Add a blacklist entry."""
        self._validate_item_type(item_type)
        if pattern_type == 'exact':
            self.blacklist[item_type].add_exact(name, source, case_sensitive)
        else:
            self.blacklist[item_type].add_pattern(
                name, pattern_type, case_sensitive, source
            )
    
    def add_whitelist_entry(self, item_type: str, name: str, 
                           pattern_type: str = 'exact',
                           case_sensitive: bool = True,
                           source: str = 'user'):
        """Add a whitelist entry."""
        self._validate_item_type(item_type)
        
        if pattern_type == 'exact':
            self.whitelist[item_type].add_exact(name, source, case_sensitive)
        else:
            self.whitelist[item_type].add_pattern(
                name, pattern_type, case_sensitive, source
            )
    
    def is_allowed(self, item_type: str, item_name: str) -> bool:
        """
        Main query method: is this item allowed to be fuzzed?
        
        Logic:
        - Mode 'blacklist': Allow everything except blacklisted
        - Mode 'whitelist': Deny everything except whitelisted
        - Mode 'both': Whitelist overrides blacklist, then apply blacklist rules
        
        Args:
            item_type: Type of item ('module', 'method', 'class', 'object', 'function')
            item_name: Name of the item to check
            
        Returns:
            True if item is allowed, False if filtered out
        """
        self._validate_item_type(item_type)
        
        # Check whitelist first (always overrides in 'both' mode)
        wl_matched, wl_pattern = self.whitelist[item_type].matches(item_name)
        
        if self.mode == 'whitelist':
            # In whitelist mode, must match whitelist to be allowed
            if wl_matched:
                if self.verbose:
                    self._log_match('whitelist', item_type, item_name, wl_pattern)
                return True
            else:
                if self.verbose:
                    self._log_no_match('whitelist', item_type, item_name)
                return False
        
        elif self.mode == 'both':
            # Whitelist overrides blacklist
            if wl_matched:
                if self.verbose:
                    self._log_match('whitelist', item_type, item_name, wl_pattern)
                return True
            
            # Not whitelisted, check blacklist
            bl_matched, bl_pattern = self.blacklist[item_type].matches(item_name)
            if bl_matched:
                if self.verbose:
                    self._log_match('blacklist', item_type, item_name, bl_pattern)
                return False
            
            # Not blacklisted either, allow
            if self.verbose:
                self._log_match('blacklist', item_type, item_name, bl_pattern)
            return True
        
        else:  # mode == 'blacklist'
            # Whitelist can override blacklist even in blacklist mode
            if wl_matched:
                if self.verbose:
                    self._log_match('whitelist', item_type, item_name, wl_pattern)
                return True
            
            # Check blacklist
            bl_matched, bl_pattern = self.blacklist[item_type].matches(item_name)
            if bl_matched:
                if self.verbose:
                    self._log_match('blacklist', item_type, item_name, bl_pattern)
                return False
            
            # Not blacklisted, allow
            if self.verbose:
                print(f"Allowing {item_name} because it is not blacklisted.", file=sys.stderr)
            return True
    
    def validate_whitelist_mode(self):
        """Ensure whitelist mode has at least one whitelist entry."""
        if self.mode != 'whitelist':
            return
        
        has_entries = any(
            wl.exact or wl.exact_insensitive or 
            any(p.pattern_type != 'exact' for p in wl.patterns)
            for wl in self.whitelist.values()
        )
        
        if not has_entries:
            raise ValueError(
                "Whitelist mode requires at least one whitelist entry. "
                "Use --whitelist-methods, --whitelist-classes, etc."
            )
    
    def finalize(self):
        """Finalize the filter manager (call after all registrations)."""
        self.validate_whitelist_mode()
        self._initialized = True
        
        if self.verbose:
            stats = self.get_statistics()
            print(f"[FilterManager] Mode: {stats['mode']}", file=sys.stderr)
            print(f"[FilterManager] Loaded filters:", file=sys.stderr)
            for item_type in self.ITEM_TYPES:
                bl_count = stats['blacklist'][item_type]['total']
                wl_count = stats['whitelist'][item_type]['total']
                if bl_count > 0 or wl_count > 0:
                    print(
                        f"  {item_type}: "
                        f"blacklist={bl_count}, whitelist={wl_count}",
                        file=sys.stderr
                    )
    
    def get_statistics(self) -> dict:
        """Get statistics about loaded filters."""
        stats = {
            'mode': self.mode,
            'blacklist': {},
            'whitelist': {}
        }
        
        for item_type in self.ITEM_TYPES:
            bl = self.blacklist[item_type]
            wl = self.whitelist[item_type]
            
            bl_pattern_count = sum(
                1 for p in bl.patterns if p.pattern_type != 'exact'
            )
            wl_pattern_count = sum(
                1 for p in wl.patterns if p.pattern_type != 'exact'
            )
            
            stats['blacklist'][item_type] = {
                'exact': len(bl.exact) + len(bl.exact_insensitive),
                'patterns': bl_pattern_count,
                'total': len(bl.exact) + len(bl.exact_insensitive) + bl_pattern_count
            }
            stats['whitelist'][item_type] = {
                'exact': len(wl.exact) + len(wl.exact_insensitive),
                'patterns': wl_pattern_count,
                'total': len(wl.exact) + len(wl.exact_insensitive) + wl_pattern_count
            }
        
        return stats
    
    def _validate_item_type(self, item_type: str):
        """Validate that item_type is valid."""
        if item_type not in self.ITEM_TYPES:
            raise ValueError(
                f"Invalid item_type: {item_type}. "
                f"Must be one of: {self.ITEM_TYPES}"
            )
    
    def _log_match(self, list_type: str, item_type: str, 
                   item_name: str, pattern: FilterPattern | None):
        """Log when an item matches a filter."""
        if pattern is None:
            pattern_info = "unknown pattern"
        else:
            pattern_info = (
                f"{pattern.pattern_type}: '{pattern.pattern}', "
                f"source: {pattern.source}"
            )
        
        action = "allowed" if list_type == 'whitelist' else "filtered"
        print(
            f"[FilterManager] {list_type.capitalize()}: "
            f"{action} {item_type} '{item_name}' "
            f"(matched {pattern_info})",
            file=sys.stderr
        )
    
    def _log_no_match(self, list_type: str, item_type: str, item_name: str):
        """Log when an item doesn't match (relevant in whitelist mode)."""
        print(
            f"[FilterManager] {list_type.capitalize()}: "
            f"denied {item_type} '{item_name}' (no match)",
            file=sys.stderr
        )


# Global singleton
_filter_manager: FilterManager | None = None


def get_filter_manager() -> FilterManager:
    """Get the global FilterManager instance."""
    global _filter_manager
    if _filter_manager is None:
        raise RuntimeError(
            "FilterManager not initialized. "
            "Call create_filter_manager() first."
        )
    return _filter_manager


def create_filter_manager(mode: str = 'blacklist', 
                         verbose: bool = False) -> FilterManager:
    """Create and return the global FilterManager instance."""
    global _filter_manager
    if _filter_manager is not None:
        raise RuntimeError("FilterManager already initialized")
    
    _filter_manager = FilterManager(mode=mode, verbose=verbose)
    return _filter_manager


def reset_filter_manager():
    """Reset the global FilterManager (mainly for testing)."""
    global _filter_manager
    _filter_manager = None
