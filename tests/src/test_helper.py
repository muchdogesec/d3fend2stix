"""Tests for helper.py module"""
import pytest
import hashlib
import uuid
from unittest.mock import patch, MagicMock
from d3fend2stix.helper import (
    generate_uuid5,
    generate_md5_from_list,
    clean_filesystem,
    extract_id_from_uri,
    safe_get,
    ensure_list
)
from d3fend2stix.config import DEFAULT_CONFIG as config


class TestGenerateUuid5:
    """Tests for generate_uuid5 function"""
    
    def test_generate_uuid5_consistent(self):
        """Test that same input generates same UUID"""
        value = "test_value"
        uuid1 = generate_uuid5(value)
        uuid2 = generate_uuid5(value)
        assert uuid1 == uuid2
    
    def test_generate_uuid5_different_inputs(self):
        """Test that different inputs generate different UUIDs"""
        uuid1 = generate_uuid5("value1")
        uuid2 = generate_uuid5("value2")
        assert uuid1 != uuid2
    
    def test_generate_uuid5_format(self):
        """Test that output is valid UUID format"""
        result = generate_uuid5("test")
        # Should be valid UUID string
        uuid.UUID(result)  # Will raise if invalid
    
    def test_generate_uuid5_uses_namespace(self):
        """Test that UUID is generated with correct namespace"""
        value = "test_value"
        expected = str(uuid.uuid5(config.namespace, value))
        result = generate_uuid5(value)
        assert result == expected


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
            {"id": "test-1", "type": "attack-pattern"},
            {"id": "test-2", "type": "indicator"}
        ]
        hash1 = generate_md5_from_list(objects)
        hash2 = generate_md5_from_list(objects)
        assert hash1 == hash2
    
    def test_generate_md5_order_independent(self):
        """Test that object order doesn't affect hash (due to sorting)"""
        obj1 = {"id": "test-1", "type": "attack-pattern"}
        obj2 = {"id": "test-2", "type": "indicator"}
        
        hash1 = generate_md5_from_list([obj1, obj2])
        hash2 = generate_md5_from_list([obj2, obj1])
        assert hash1 == hash2
    
    def test_generate_md5_different_content(self):
        """Test that different content generates different hash"""
        objects1 = [{"id": "test-1", "type": "attack-pattern"}]
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
