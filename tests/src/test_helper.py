"""Tests for helper.py module"""
import pytest
import hashlib
import uuid
from unittest.mock import patch, MagicMock
from d3fend2stix.helper import (
    generate_stix_id,
    generate_md5_from_list,
    clean_filesystem,
    extract_id_from_uri,
    safe_get,
    ensure_list
)
from d3fend2stix.config import DEFAULT_CONFIG as config


class TestGenerateStixId:
    """Tests for generate_stix_id function"""
    
    def test_generate_stix_id_consistent(self):
        """Test that same input generates same STIX ID"""
        object_type = "course-of-action"
        value = "test_value"
        stix_id1 = generate_stix_id(object_type, value)
        stix_id2 = generate_stix_id(object_type, value)
        assert stix_id1 == stix_id2
    
    def test_generate_stix_id_different_inputs(self):
        """Test that different inputs generate different STIX IDs"""
        stix_id1 = generate_stix_id("course-of-action", "value1")
        stix_id2 = generate_stix_id("course-of-action", "value2")
        assert stix_id1 != stix_id2
    
    def test_generate_stix_id_format(self):
        """Test that output follows STIX ID format"""
        result = generate_stix_id("course-of-action", "test")
        # Should be in format: object-type--uuid
        assert result.startswith("course-of-action--")
        uuid_part = result.split("--", 1)[1]
        uuid.UUID(uuid_part)  # Will raise if invalid UUID
    
    def test_generate_stix_id_uses_namespace(self):
        """Test that STIX ID is generated with correct namespace"""
        object_type = "indicator"
        value = "test_value"
        expected_uuid = str(uuid.uuid5(config.namespace, value))
        expected = f"{object_type}--{expected_uuid}"
        result = generate_stix_id(object_type, value)
        assert result == expected
    
    def test_generate_stix_id_different_object_types(self):
        """Test that same value with different object types produces different IDs"""
        value = "same_value"
        attack_pattern_id = generate_stix_id("course-of-action", value)
        indicator_id = generate_stix_id("indicator", value)
        # Both should use same UUID but different prefixes
        assert attack_pattern_id.startswith("course-of-action--")
        assert indicator_id.startswith("indicator--")
        # Extract UUIDs - they should be the same
        uuid1 = attack_pattern_id.split("--", 1)[1]
        uuid2 = indicator_id.split("--", 1)[1]
        assert uuid1 == uuid2


class TestGenerateMd5FromList:
    """Tests for generate_md5_from_list function"""
    
    def test_generate_md5_empty_list(self):
        """Test MD5 generation from empty list"""
        result = generate_md5_from_list([])
        assert isinstance(result, str)
        assert len(result) == 32  # MD5 hash length
    
    def test_generate_md5_consistent(self):
        """Test that same objects generate same hash"""
        objects = [
            {"id": "test-1", "type": "course-of-action"},
            {"id": "test-2", "type": "indicator"}
        ]
        hash1 = generate_md5_from_list(objects)
        hash2 = generate_md5_from_list(objects)
        assert hash1 == hash2
    
    def test_generate_md5_order_independent(self):
        """Test that object order doesn't affect hash (due to sorting)"""
        obj1 = {"id": "test-1", "type": "course-of-action"}
        obj2 = {"id": "test-2", "type": "indicator"}
        
        hash1 = generate_md5_from_list([obj1, obj2])
        hash2 = generate_md5_from_list([obj2, obj1])
        assert hash1 == hash2
    
    def test_generate_md5_different_content(self):
        """Test that different content generates different hash"""
        objects1 = [{"id": "test-1", "type": "course-of-action"}]
        objects2 = [{"id": "test-2", "type": "indicator"}]
        
        hash1 = generate_md5_from_list(objects1)
        hash2 = generate_md5_from_list(objects2)
        assert hash1 != hash2


class TestCleanFilesystem:
    """Tests for clean_filesystem function"""
    
    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('os.unlink')
    @patch('shutil.rmtree')
    def test_clean_filesystem_default_path(self, mock_rmtree, mock_unlink, mock_listdir, mock_exists):
        """Test cleaning filesystem with default path"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'dir1']
        
        with patch('os.path.isfile', side_effect=[True, False]):
            with patch('os.path.islink', return_value=False):
                with patch('os.path.isdir', side_effect=[False, True]):
                    clean_filesystem()
        
        mock_exists.assert_called_once()
        mock_listdir.assert_called()
    
    @patch('os.path.exists')
    @patch('os.listdir')
    def test_clean_filesystem_custom_path(self, mock_listdir, mock_exists):
        """Test cleaning filesystem with custom path"""
        custom_path = "/custom/path"
        mock_exists.return_value = True
        mock_listdir.return_value = []
        
        clean_filesystem(custom_path)
        
        mock_exists.assert_called_once_with(custom_path)
    
    @patch('os.path.exists')
    def test_clean_filesystem_nonexistent_path(self, mock_exists):
        """Test cleaning filesystem when path doesn't exist"""
        mock_exists.return_value = False
        
        # Should not raise error
        clean_filesystem()
    
    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('os.unlink')
    def test_clean_filesystem_handles_errors(self, mock_unlink, mock_listdir, mock_exists):
        """Test that errors during deletion are handled gracefully"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt']
        mock_unlink.side_effect = Exception("Permission denied")
        
        with patch('os.path.isfile', return_value=True):
            with patch('os.path.islink', return_value=False):
                # Should not raise, just log error
                clean_filesystem()


class TestExtractIdFromUri:
    """Tests for extract_id_from_uri function"""
    
    def test_extract_id_with_colon(self):
        """Test extracting ID from URI with colon separator"""
        assert extract_id_from_uri("d3f:Detect") == "Detect"
        assert extract_id_from_uri("rdfs:label") == "label"
    
    def test_extract_id_without_colon(self):
        """Test extracting ID from URI without colon"""
        assert extract_id_from_uri("Detect") == "Detect"
        assert extract_id_from_uri("simple_id") == "simple_id"
    
    def test_extract_id_multiple_colons(self):
        """Test extracting ID from URI with multiple colons"""
        assert extract_id_from_uri("a:b:c:d") == "d"
    
    def test_extract_id_empty_string(self):
        """Test extracting ID from empty string"""
        assert extract_id_from_uri("") == ""
    
    def test_extract_id_http_url(self):
        """Test extracting ID from HTTP URL"""
        result = extract_id_from_uri("http://example.com/resource")
        assert result == "//example.com/resource"


class TestSafeGet:
    """Tests for safe_get function"""
    
    def test_safe_get_simple_value(self):
        """Test getting simple value from dict"""
        obj = {"key": "value"}
        assert safe_get(obj, "key") == "value"
    
    def test_safe_get_missing_key(self):
        """Test getting missing key returns default"""
        obj = {"key": "value"}
        assert safe_get(obj, "missing") is None
        assert safe_get(obj, "missing", "default") == "default"
    
    def test_safe_get_with_id_reference(self):
        """Test getting value that is an @id reference"""
        obj = {"key": {"@id": "d3f:Resource"}}
        assert safe_get(obj, "key") == "d3f:Resource"
    
    def test_safe_get_dict_without_id(self):
        """Test getting dict value without @id"""
        obj = {"key": {"name": "test"}}
        assert safe_get(obj, "key") == {"name": "test"}
    
    def test_safe_get_none_value(self):
        """Test getting None value"""
        obj = {"key": None}
        assert safe_get(obj, "key") is None
    
    def test_safe_get_numeric_value(self):
        """Test getting numeric value"""
        obj = {"count": 42}
        assert safe_get(obj, "count") == 42


class TestEnsureList:
    """Tests for ensure_list function"""
    
    def test_ensure_list_with_list(self):
        """Test that lists are returned as-is"""
        input_list = [1, 2, 3]
        assert ensure_list(input_list) == input_list
    
    def test_ensure_list_with_single_value(self):
        """Test that single values are wrapped in list"""
        assert ensure_list("value") == ["value"]
        assert ensure_list(42) == [42]
        assert ensure_list({"key": "value"}) == [{"key": "value"}]
    
    def test_ensure_list_with_none(self):
        """Test that None returns empty list"""
        assert ensure_list(None) == []
    
    def test_ensure_list_with_empty_list(self):
        """Test that empty list is returned as-is"""
        assert ensure_list([]) == []
    
    def test_ensure_list_with_string(self):
        """Test that string is wrapped in list"""
        assert ensure_list("test") == ["test"]
    
    def test_ensure_list_with_dict(self):
        """Test that dict is wrapped in list"""
        test_dict = {"key": "value"}
        result = ensure_list(test_dict)
        assert result == [test_dict]
        assert len(result) == 1
