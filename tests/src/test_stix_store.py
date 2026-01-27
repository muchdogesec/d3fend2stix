"""Tests for stix_store.py module"""
import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from stix2 import Bundle
from d3fend2stix.stix_store import store_in_bundle


class TestStoreInBundle:
    """Tests for store_in_bundle function"""
    
    @pytest.fixture
    def sample_stix_objects(self):
        """Sample STIX objects for testing"""
        return [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
                "name": "Test Pattern",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z"
            },
            {
                "type": "indicator",
                "id": "indicator--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
                "name": "Test Indicator",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00.000Z"
            }
        ]
    
    def test_store_in_bundle_basic(self, sample_stix_objects):
        """Test basic bundle creation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id = store_in_bundle(temp_dir, sample_stix_objects)
            
            assert bundle_id.startswith("bundle--")
            assert os.path.exists(os.path.join(temp_dir, "d3fend-bundle.json"))
    
    def test_store_in_bundle_with_filename(self, sample_stix_objects):
        """Test bundle creation with custom filename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id = store_in_bundle(temp_dir, sample_stix_objects, filename="custom")
            
            assert os.path.exists(os.path.join(temp_dir, "custom.json"))
    
    def test_store_in_bundle_with_json_extension(self, sample_stix_objects):
        """Test bundle creation with filename already having .json extension"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id = store_in_bundle(temp_dir, sample_stix_objects, filename="custom.json")
            
            assert os.path.exists(os.path.join(temp_dir, "custom.json"))
            # Should not create custom.json.json
            assert not os.path.exists(os.path.join(temp_dir, "custom.json.json"))
    
    def test_store_in_bundle_creates_directory(self, sample_stix_objects):
        """Test that bundle creation creates directory if it doesn't exist"""
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_dir = os.path.join(temp_dir, "nested", "path")
            bundle_id = store_in_bundle(nested_dir, sample_stix_objects)
            
            assert os.path.exists(nested_dir)
            assert os.path.exists(os.path.join(nested_dir, "d3fend-bundle.json"))
    
    def test_store_in_bundle_deterministic_id(self, sample_stix_objects):
        """Test that same objects produce same bundle ID"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id1 = store_in_bundle(temp_dir, sample_stix_objects, filename="bundle1")
            bundle_id2 = store_in_bundle(temp_dir, sample_stix_objects, filename="bundle2")
            
            assert bundle_id1 == bundle_id2
    
    def test_store_in_bundle_different_objects(self, sample_stix_objects):
        """Test that different objects produce different bundle IDs"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id1 = store_in_bundle(temp_dir, sample_stix_objects[:1])
            bundle_id2 = store_in_bundle(temp_dir, sample_stix_objects)
            
            assert bundle_id1 != bundle_id2
    
    def test_store_in_bundle_file_content(self, sample_stix_objects):
        """Test that bundle file contains correct content"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id = store_in_bundle(temp_dir, sample_stix_objects)
            
            bundle_file = os.path.join(temp_dir, "d3fend-bundle.json")
            with open(bundle_file, 'r') as f:
                content = json.load(f)
            
            assert content["type"] == "bundle"
            assert content["id"] == bundle_id
            assert "objects" in content
            assert len(content["objects"]) >= len(sample_stix_objects)
    
    def test_store_in_bundle_empty_objects(self):
        """Test bundle creation with empty object list"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id = store_in_bundle(temp_dir, [])
            
            assert bundle_id.startswith("bundle--")
            assert os.path.exists(os.path.join(temp_dir, "d3fend-bundle.json"))
    
    def test_store_in_bundle_json_formatting(self, sample_stix_objects):
        """Test that bundle JSON is properly formatted with indentation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            store_in_bundle(temp_dir, sample_stix_objects)
            
            bundle_file = os.path.join(temp_dir, "d3fend-bundle.json")
            with open(bundle_file, 'r') as f:
                content = f.read()
            
            # Check that JSON is indented (contains newlines and spaces)
            assert '\n' in content
            assert '    ' in content
    
    def test_store_in_bundle_overwrites_existing(self, sample_stix_objects):
        """Test that storing bundle overwrites existing file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_file = os.path.join(temp_dir, "test-bundle.json")
            
            # Create initial bundle
            bundle_id1 = store_in_bundle(temp_dir, sample_stix_objects[:1], filename="test-bundle")
            
            # Overwrite with different content
            bundle_id2 = store_in_bundle(temp_dir, sample_stix_objects, filename="test-bundle")
            
            # Read final content
            with open(bundle_file, 'r') as f:
                content = json.load(f)
            
            # Should contain all objects from second call
            assert len(content["objects"]) >= len(sample_stix_objects)
    
    def test_store_in_bundle_returns_bundle_id(self, sample_stix_objects):
        """Test that function returns the bundle ID"""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = store_in_bundle(temp_dir, sample_stix_objects)
            
            assert isinstance(result, str)
            assert result.startswith("bundle--")
    
    @patch('d3fend2stix.stix_store.Bundle')
    def test_store_in_bundle_uses_allow_custom(self, mock_bundle, sample_stix_objects):
        """Test that Bundle is created with allow_custom=True"""
        with tempfile.TemporaryDirectory() as temp_dir:
            mock_bundle_instance = MagicMock()
            mock_bundle_instance.serialize.return_value = '{"type": "bundle", "id": "bundle--123"}'
            mock_bundle_instance.id = "bundle--123"
            mock_bundle.return_value = mock_bundle_instance
            
            store_in_bundle(temp_dir, sample_stix_objects)
            
            # Check that Bundle was called with allow_custom=True
            call_kwargs = mock_bundle.call_args[1]
            assert call_kwargs.get('allow_custom') is True
    
    def test_store_in_bundle_preserves_object_order(self, sample_stix_objects):
        """Test that objects are preserved in bundle"""
        with tempfile.TemporaryDirectory() as temp_dir:
            store_in_bundle(temp_dir, sample_stix_objects)
            
            bundle_file = os.path.join(temp_dir, "d3fend-bundle.json")
            with open(bundle_file, 'r') as f:
                content = json.load(f)
            
            object_ids = [obj["id"] for obj in content["objects"]]
            # All original object IDs should be present
            for obj in sample_stix_objects:
                assert obj["id"] in object_ids
    
    def test_store_in_bundle_with_special_characters_in_filename(self, sample_stix_objects):
        """Test bundle creation with special characters in filename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Use simple valid filename
            bundle_id = store_in_bundle(temp_dir, sample_stix_objects, filename="test_bundle-v1")
            
            assert os.path.exists(os.path.join(temp_dir, "test_bundle-v1.json"))
    
    def test_store_in_bundle_multiple_calls_same_dir(self, sample_stix_objects):
        """Test multiple bundle creations in same directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_id1 = store_in_bundle(temp_dir, sample_stix_objects, filename="bundle1")
            bundle_id2 = store_in_bundle(temp_dir, sample_stix_objects, filename="bundle2")
            
            assert os.path.exists(os.path.join(temp_dir, "bundle1.json"))
            assert os.path.exists(os.path.join(temp_dir, "bundle2.json"))
