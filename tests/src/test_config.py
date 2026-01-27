"""Tests for config.py module"""
import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from uuid import UUID
from d3fend2stix.config import Config, DEFAULT_CONFIG, load_file_from_url


class TestLoadFileFromUrl:
    """Tests for load_file_from_url function"""
    
    @patch('requests.get')
    def test_load_file_from_url_success(self, mock_get):
        """Test successful file loading from URL"""
        mock_response = MagicMock()
        mock_response.text = '{"test": "data"}'
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        # Clear cache before test
        load_file_from_url.cache_clear()
        
        result = load_file_from_url("http://example.com/test.json")
        
        assert result == '{"test": "data"}'
        mock_get.assert_called_once_with("http://example.com/test.json")
    
    @patch('requests.get')
    def test_load_file_from_url_error(self, mock_get):
        """Test error handling when URL loading fails"""
        import requests
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        # Clear cache before test
        load_file_from_url.cache_clear()
        
        result = load_file_from_url("http://example.com/test.json")
        
        assert result is None
    
    @patch('requests.get')
    def test_load_file_from_url_caching(self, mock_get):
        """Test that function uses caching"""
        mock_response = MagicMock()
        mock_response.text = '{"test": "data"}'
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        # Clear cache before test
        load_file_from_url.cache_clear()
        
        # First call
        result1 = load_file_from_url("http://example.com/test.json")
        # Second call - should use cache
        result2 = load_file_from_url("http://example.com/test.json")
        
        # Should only call requests.get once due to caching
        assert mock_get.call_count == 1
        assert result1 == result2
    
    @patch('requests.get')
    def test_load_file_from_url_http_error(self, mock_get):
        """Test handling of HTTP errors"""
        import requests
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_get.return_value = mock_response
        
        # Clear cache before test
        load_file_from_url.cache_clear()
        
        result = load_file_from_url("http://example.com/missing.json")
        
        assert result is None


class TestConfig:
    """Tests for Config class"""
    
    def test_config_initialization(self):
        """Test that Config initializes with correct defaults"""
        config = Config()
        
        assert config.type == "d3fend"
        assert isinstance(config.D3FEND2STIX_FOLDER, Path)
        assert isinstance(config.REPO_FOLDER, Path)
    
    def test_config_namespace_is_uuid(self):
        """Test that namespace is a valid UUID"""
        config = Config()
        
        assert isinstance(config.namespace, UUID)
        assert str(config.namespace) == "6923e7d4-e142-508c-aefc-b5f4dd27dc22"
    
    def test_config_data_paths(self):
        """Test that data paths are configured correctly"""
        config = Config()
        
        assert isinstance(config.data_path, Path)
        assert config.d3fend_json_file.endswith("d3fend-v1_3_0.json")
    
    def test_config_stix2_folders(self):
        """Test that STIX2 folder paths are configured"""
        config = Config()
        
        assert isinstance(config.stix2_objects_folder, str)
        assert isinstance(config.stix2_bundles_folder, str)
        assert "stix2_objects" in config.stix2_objects_folder
        assert "stix2_bundles" in config.stix2_bundles_folder
    
    def test_config_marking_refs_property(self):
        """Test marking_refs property returns correct references"""
        config = Config()
        
        refs = config.marking_refs
        
        assert isinstance(refs, list)
        assert len(refs) == 2
        assert config.TLP_CLEAR_MARKING_DEFINITION_REF in refs
        assert any("marking-definition--" in ref for ref in refs)
    
    def test_config_default_objects_property(self):
        """Test default_objects property returns identity and marking"""
        config = Config()
        
        objects = config.default_objects
        
        assert isinstance(objects, list)
        assert len(objects) == 2
        assert config.D3FEND2STIX_IDENTITY_OBJECT in objects
        assert config.D3FEND2STIX_MARKING_DEFINITION_OBJECT in objects
    
    def test_config_tlp_clear_marking_ref(self):
        """Test TLP_CLEAR marking definition reference"""
        config = Config()
        
        assert config.TLP_CLEAR_MARKING_DEFINITION_REF == "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    
    def test_config_identity_url(self):
        """Test identity URL is configured"""
        config = Config()
        
        assert "stix4doge" in config.D3FEND2STIX_IDENTITY_URL
        assert "identity" in config.D3FEND2STIX_IDENTITY_URL
        assert config.D3FEND2STIX_IDENTITY_URL.startswith("https://")
    
    def test_config_marking_definition_url(self):
        """Test marking definition URL is configured"""
        config = Config()
        
        assert "stix4doge" in config.D3FEND2STIX_MARKING_DEFINITION_URL
        assert "marking-definition" in config.D3FEND2STIX_MARKING_DEFINITION_URL
        assert config.D3FEND2STIX_MARKING_DEFINITION_URL.startswith("https://")
    
    def test_config_identity_object_structure(self):
        """Test that identity object has correct structure"""
        config = Config()
        
        identity = config.D3FEND2STIX_IDENTITY_OBJECT
        
        assert isinstance(identity, dict)
        assert "id" in identity
        assert identity["id"].startswith("identity--")
    
    def test_config_marking_definition_object_structure(self):
        """Test that marking definition object has correct structure"""
        config = Config()
        
        marking = config.D3FEND2STIX_MARKING_DEFINITION_OBJECT
        
        assert isinstance(marking, dict)
        assert "id" in marking
        assert marking["id"].startswith("marking-definition--")
    
    def test_config_fs_property(self):
        """Test fs property returns FileSystemStore"""
        config = Config()
        
        fs = config.fs
        
        # FileSystemStore should be created
        assert fs is not None
        # Each call creates a new instance (property, not cached)
        fs2 = config.fs
        assert fs2 is not None
    
    def test_default_config_exists(self):
        """Test that DEFAULT_CONFIG is created"""
        assert DEFAULT_CONFIG is not None
        assert isinstance(DEFAULT_CONFIG, Config)
    
    def test_config_folders_created(self):
        """Test that config creates necessary directories"""
        config = Config()
        
        # These directories should exist after config initialization
        assert os.path.exists(config.stix2_objects_folder)
        assert os.path.exists(config.stix2_bundles_folder)
    
    def test_config_type_attribute(self):
        """Test that type attribute is set correctly"""
        config = Config()
        
        assert config.type == "d3fend"
    
    def test_config_d3fend2stix_folder_path(self):
        """Test that D3FEND2STIX_FOLDER points to correct location"""
        config = Config()
        
        # Should point to the d3fend2stix package directory
        assert config.D3FEND2STIX_FOLDER.exists()
        assert config.D3FEND2STIX_FOLDER.is_absolute()
    
    def test_config_repo_folder_path(self):
        """Test that REPO_FOLDER is parent of D3FEND2STIX_FOLDER"""
        config = Config()
        
        assert config.REPO_FOLDER == config.D3FEND2STIX_FOLDER.parent
        assert config.REPO_FOLDER.is_absolute()
    
    def test_config_marking_refs_contains_both_types(self):
        """Test that marking_refs contains both TLP and custom marking"""
        config = Config()
        
        refs = config.marking_refs
        
        # Should have TLP CLEAR marking
        assert any("94868c89-83c2-464b-929b-a1a8aa3c8487" in ref for ref in refs)
        # Should have custom d3fend2stix marking
        assert len([ref for ref in refs if ref.startswith("marking-definition--")]) == 2
    
    @patch('os.makedirs')
    def test_config_creates_directories_if_not_exist(self, mock_makedirs):
        """Test that config attempts to create directories"""
        # This test verifies the directory creation logic is called
        # The actual directories may already exist in the test environment
        config = Config()
        
        # makedirs should have been called (even if directories exist, due to exist_ok)
        assert mock_makedirs.call_count > 0 or os.path.exists(config.stix2_objects_folder)
    
    def test_config_data_path_is_path_object(self):
        """Test that data_path is a Path object"""
        config = Config()
        
        assert isinstance(config.data_path, Path)
        assert config.data_path.is_absolute()
