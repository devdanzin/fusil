"""
Blacklist Configuration Loader for Fusil

Loads filter configuration from fusil_blacklist.toml files.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fusil.filter_manager import FilterManager

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for Python < 3.11
    except ImportError:
        tomllib = None  # type: ignore

from fusil.filter_manager import detect_pattern_type


class BlacklistConfigLoader:
    """Loads filter configuration from fusil_blacklist.toml."""
    
    def __init__(self, config_path: Path | str):
        self.config_path = Path(config_path)
    
    def load(self, filter_manager: FilterManager):
        """
        Load config file and populate filter_manager.
        
        Args:
            filter_manager: The FilterManager instance to populate
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ImportError: If toml library not available
            ValueError: If config format is invalid
        """
        if tomllib is None:
            raise ImportError(
                "TOML library not available. "
                "Install tomli for Python < 3.11 or upgrade to Python 3.11+"
            )
        
        if not self.config_path.exists():
            # Config file is optional, silently return
            return
        
        print(
            f"[FilterManager] Loading config from {self.config_path}",
            file=sys.stderr
        )
        
        with open(self.config_path, 'rb') as f:
            config = tomllib.load(f)
        
        # Load options
        options = config.get('options', {})
        default_case_sensitive = options.get('case_sensitive', True)

        # Load blacklist entries
        if 'blacklist' in config:
            self._load_filter_list(
                filter_manager, 
                config['blacklist'], 
                'blacklist',
                default_case_sensitive
            )
        
        # Load whitelist entries
        if 'whitelist' in config:
            self._load_filter_list(
                filter_manager,
                config['whitelist'],
                'whitelist',
                default_case_sensitive
            )
        
        print(
            f"[FilterManager] Successfully loaded config from {self.config_path}",
            file=sys.stderr
        )
    
    def _load_filter_list(self, filter_manager: FilterManager,
                         config_section: dict, list_type: str,
                         default_case_sensitive: bool):
        """
        Load entries from a config section.
        
        Args:
            filter_manager: FilterManager to add entries to
            config_section: The [blacklist] or [whitelist] section
            list_type: 'blacklist' or 'whitelist'
            default_case_sensitive: Default case sensitivity setting
        """
        for item_type in filter_manager.ITEM_TYPES:
            if item_type not in config_section:
                print(f"Missing item type: {item_type}", file=sys.stderr)
                continue
            
            entries = config_section[item_type]

            # Handle simple list format
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, str):
                        self._add_entry_from_string(
                            filter_manager, list_type, item_type,
                            entry, default_case_sensitive
                        )
                    elif isinstance(entry, dict):
                        # Detailed format with per-entry options
                        self._add_entry_from_dict(
                            filter_manager, list_type, item_type,
                            entry, default_case_sensitive
                        )
                    else:
                        print(
                            f"[FilterManager] WARNING: Invalid entry type "
                            f"in {list_type}.{item_type}: {type(entry)}",
                            file=sys.stderr
                        )
    
    def _add_entry_from_string(self, filter_manager: FilterManager,
                               list_type: str, item_type: str,
                               entry: str, default_case_sensitive: bool):
        """Parse an entry string and add to filter manager."""
        if not entry or not entry.strip():
            return
        
        entry = entry.strip()

        # Auto-detect pattern type
        pattern_type = detect_pattern_type(entry)
        
        if list_type == 'blacklist':
            filter_manager.add_blacklist_entry(
                item_type, entry, pattern_type,
                default_case_sensitive, source='config'
            )
        else:
            filter_manager.add_whitelist_entry(
                item_type, entry, pattern_type,
                default_case_sensitive, source='config'
            )
    
    def _add_entry_from_dict(self, filter_manager: FilterManager,
                            list_type: str, item_type: str,
                            entry_dict: dict, default_case_sensitive: bool):
        """
        Parse an entry dictionary with options.
        
        Format:
            {
                "pattern": "_private*",
                "type": "glob",  # optional, auto-detected if not specified
                "case_sensitive": false  # optional
            }
        """
        if 'pattern' not in entry_dict:
            print(
                f"[FilterManager] WARNING: Entry dict missing 'pattern' field "
                f"in {list_type}.{item_type}",
                file=sys.stderr
            )
            return
        
        pattern = entry_dict['pattern']
        pattern_type = entry_dict.get('type')
        case_sensitive = entry_dict.get('case_sensitive', default_case_sensitive)
        
        # Auto-detect if not specified
        if pattern_type is None:
            pattern_type = detect_pattern_type(pattern)
        
        # Validate pattern_type
        if pattern_type not in ('exact', 'glob', 'regex'):
            print(
                f"[FilterManager] WARNING: Invalid pattern type '{pattern_type}' "
                f"for pattern '{pattern}', using auto-detection",
                file=sys.stderr
            )
            pattern_type = detect_pattern_type(pattern)
        
        if list_type == 'blacklist':
            filter_manager.add_blacklist_entry(
                item_type, pattern, pattern_type,
                case_sensitive, source='config'
            )
        else:
            filter_manager.add_whitelist_entry(
                item_type, pattern, pattern_type,
                case_sensitive, source='config'
            )


def load_blacklist_config(config_path: Path | str,
                         filter_manager: FilterManager):
    """
    Convenience function to load config.
    
    Args:
        config_path: Path to fusil_blacklist.toml
        filter_manager: FilterManager instance to populate
    """
    loader = BlacklistConfigLoader(config_path)
    loader.load(filter_manager)
