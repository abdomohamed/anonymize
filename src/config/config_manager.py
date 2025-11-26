"""
Configuration manager for loading and managing application configuration.

This module handles loading configuration from YAML files and providing
access to configuration options throughout the application.
"""

import os
import yaml
from typing import Dict, Any, Optional
from src.models import Config


class ConfigManager:
    """
    Manager for loading and accessing configuration.
    
    Configuration is loaded from multiple sources in this order:
    1. Default configuration (config/default_config.yaml)
    2. User-provided configuration file
    3. Environment variables (for sensitive data)
    4. CLI argument overrides
    """
    
    def __init__(self, default_config_path: str):
        """
        Initialize configuration manager.
        
        Args:
            default_config_path: Path to default configuration file
        """
        self.default_config_path = default_config_path
        self.config_data: Dict[str, Any] = {}
    
    @classmethod
    def load(
        cls,
        default_path: str = "config/default_config.yaml",
        user_path: Optional[str] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> 'ConfigManager':
        """
        Load configuration from multiple sources.
        
        Args:
            default_path: Path to default configuration
            user_path: Optional path to user configuration file
            cli_overrides: Optional dictionary of CLI argument overrides
            
        Returns:
            ConfigManager instance with loaded configuration
        """
        manager = cls(default_path)
        
        # Load default configuration
        manager._load_yaml(default_path)
        
        # Load user configuration if provided
        if user_path and os.path.exists(user_path):
            user_config = manager._load_yaml_file(user_path)
            manager._merge_config(user_config)
        
        # Apply environment variable overrides
        manager._apply_env_overrides()
        
        # Apply CLI overrides
        if cli_overrides:
            manager._merge_config(cli_overrides)
        
        return manager
    
    def _load_yaml(self, path: str) -> None:
        """
        Load YAML configuration file.
        
        Args:
            path: Path to YAML file
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(f"Warning: Configuration file not found: {path}")
            self.config_data = {}
        except yaml.YAMLError as e:
            print(f"Error parsing YAML configuration: {e}")
            self.config_data = {}
    
    def _load_yaml_file(self, path: str) -> Dict[str, Any]:
        """
        Load YAML file and return as dictionary.
        
        Args:
            path: Path to YAML file
            
        Returns:
            Dictionary with configuration data
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading configuration from {path}: {e}")
            return {}
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """
        Merge new configuration into existing configuration.
        
        Args:
            new_config: New configuration dictionary to merge
        """
        self._deep_merge(self.config_data, new_config)
    
    def _deep_merge(self, base: Dict, update: Dict) -> None:
        """
        Deep merge update dictionary into base dictionary.
        
        Args:
            base: Base dictionary to update
            update: Dictionary with updates
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        # Hash salt from environment (security best practice)
        env_salt = os.getenv('PII_ANONYMIZE_SALT')
        if env_salt:
            if 'anonymization' not in self.config_data:
                self.config_data['anonymization'] = {}
            if 'hash' not in self.config_data['anonymization']:
                self.config_data['anonymization']['hash'] = {}
            self.config_data['anonymization']['hash']['salt'] = env_salt
        
        # Log level from environment
        env_log_level = os.getenv('PII_ANONYMIZE_LOG_LEVEL')
        if env_log_level:
            if 'logging' not in self.config_data:
                self.config_data['logging'] = {}
            self.config_data['logging']['level'] = env_log_level
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Supports dot notation for nested keys (e.g., "detection.confidence_threshold")
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_detection_config(self) -> Dict[str, Any]:
        """
        Get detection configuration.
        
        Returns:
            Detection configuration dictionary
        """
        return self.config_data.get('detection', {})
    
    def get_anonymization_config(self) -> Dict[str, Any]:
        """
        Get anonymization configuration.
        
        Returns:
            Anonymization configuration dictionary
        """
        return self.config_data.get('anonymization', {})
    
    def get_processing_config(self) -> Dict[str, Any]:
        """
        Get processing configuration.
        
        Returns:
            Processing configuration dictionary
        """
        return self.config_data.get('processing', {})
    
    def get_whitelist(self) -> Dict[str, Any]:
        """
        Get whitelist configuration.
        
        Returns:
            Whitelist dictionary
        """
        return self.config_data.get('whitelist', {})
    
    def get_blacklist(self) -> list:
        """
        Get blacklist configuration.
        
        Returns:
            List of blacklisted values
        """
        return self.config_data.get('blacklist', [])
    
    def to_config_object(self) -> Config:
        """
        Convert to Config dataclass.
        
        Returns:
            Config object
        """
        return Config(
            detection=self.get_detection_config(),
            anonymization=self.get_anonymization_config(),
            processing=self.get_processing_config(),
            whitelist=self.get_whitelist(),
            blacklist=self.get_blacklist(),
            logging=self.config_data.get('logging', {})
        )
    
    def __repr__(self) -> str:
        """String representation."""
        return f"ConfigManager(loaded={len(self.config_data)} sections)"
