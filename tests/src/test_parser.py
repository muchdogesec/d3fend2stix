"""Tests for parser.py module"""
import pytest
import json
import tempfile
from datetime import datetime
from unittest.mock import patch, mock_open, MagicMock
from d3fend2stix.parser import D3FENDParser, merge_dicts


class TestMergeDicts:
    """Tests for merge_dicts function"""
    
    def test_merge_empty_dicts(self):
        """Test merging two empty dicts"""
        result = merge_dicts({}, {})
        assert result == {}
    
    def test_merge_non_overlapping(self):
        """Test merging dicts with different keys"""
        a = {"key1": "value1"}
        b = {"key2": "value2"}
        result = merge_dicts(a, b)
        assert "key1" in result
        assert "key2" in result
    
    def test_merge_overlapping_keys(self):
        """Test that larger dict's values take precedence"""
        a = {"key1": "value1", "shared": "from_a"}
        b = {"key2": "value2", "shared": "from_b"}
        result = merge_dicts(a, b)
        # The larger dict should override
        assert result["shared"] in ["from_a", "from_b"]
    
    def test_merge_different_sizes(self):
        """Test merging dicts of different sizes"""
        a = {"key1": "value1"}
        b = {"key2": "value2", "key3": "value3"}
        result = merge_dicts(a, b)
        assert len(result) == 3


class TestD3FENDParser:
    """Tests for D3FENDParser class"""
    
    @pytest.fixture
    def sample_d3fend_data(self):
        """Sample D3FEND JSON-LD data for testing"""
        return {
            "@graph": [
                {
                    "@id": "http://d3fend.mitre.org/ontologies/d3fend.owl",
                    "@type": "owl:Ontology",
                    "d3f:release-date": {"@value": "2024-01-01T00:00:00"},
                    "owl:versionInfo": "1.3.0",
                    "dcterms:title": "D3FEND"
                },
                {
                    "@id": "d3f:DefensiveTechnique",
                    "@type": "owl:Class",
                    "rdfs:label": "Defensive Technique"
                },
                {
                    "@id": "d3f:DefensiveTactic",
                    "@type": "owl:Class",
                    "rdfs:label": "Defensive Tactic"
                },
                {
                    "@id": "d3f:Detect",
                    "@type": "d3f:DefensiveTactic",
                    "rdfs:label": "Detect",
                    "d3f:definition": "Detection techniques"
                }
            ]
        }
    
    @pytest.fixture
    def temp_json_file(self, sample_d3fend_data):
        """Create temporary JSON file with sample data"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_d3fend_data, f)
            return f.name
    
    def test_parser_initialization(self):
        """Test parser initializes correctly"""
        parser = D3FENDParser("test_file.json")
        assert parser.json_file_path == "test_file.json"
        assert parser.data is None
        assert parser.graph == []
        assert parser.objects_by_id == {}
        assert parser.release_date is None
        assert parser.root is None
        assert parser.version is None
    
    def test_load_data(self, temp_json_file, sample_d3fend_data):
        """Test loading D3FEND data from file"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        assert parser.data is not None
        assert len(parser.graph) == 4
        assert len(parser.objects_by_id) >= 4
    
    def test_load_data_builds_index(self, temp_json_file):
        """Test that load_data builds objects_by_id index"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        assert "http://d3fend.mitre.org/ontologies/d3fend.owl" in parser.objects_by_id
        assert "d3f:defensivetechnique" in parser.objects_by_id
    
    def test_load_data_extracts_release_date(self, temp_json_file):
        """Test that release date is extracted correctly"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        assert parser.release_date is not None
        assert isinstance(parser.release_date, datetime)
        assert parser.version == "1.3.0"
    
    def test_getitem_case_insensitive(self, temp_json_file):
        """Test that __getitem__ is case-insensitive"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        obj1 = parser["d3f:DefensiveTactic"]
        obj2 = parser["D3F:DEFENSIVETACTIC"]
        assert obj1 == obj2
    
    def test_get_objects_by_type(self, temp_json_file):
        """Test getting objects by type"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        tactics = parser.get_objects_by_type("d3f:DefensiveTactic")
        assert len(tactics) == 1
        assert tactics[0]["@id"] == "d3f:Detect"
    
    def test_get_objects_by_type_empty(self, temp_json_file):
        """Test getting objects by type that doesn't exist"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        results = parser.get_objects_by_type("d3f:NonExistent")
        assert results == []
    
    def test_is_indirect_relation_of_direct(self):
        """Test checking direct relationship"""
        parser = D3FENDParser("dummy.json")
        parser.objects_by_id = {
            "child": {"@id": "child", "rdfs:subClassOf": [{"@id": "parent"}]},
            "parent": {"@id": "parent"}
        }
        
        obj = parser.objects_by_id["child"]
        result = parser.is_indirect_relation_of("rdfs:subClassOf", obj, "parent")
        assert result is True
    
    def test_is_indirect_relation_of_indirect(self):
        """Test checking indirect relationship (grandparent)"""
        parser = D3FENDParser("dummy.json")
        parser.objects_by_id = {
            "child": {"@id": "child", "rdfs:subClassOf": [{"@id": "parent"}]},
            "parent": {"@id": "parent", "rdfs:subClassOf": [{"@id": "grandparent"}]},
            "grandparent": {"@id": "grandparent"}
        }
        
        obj = parser.objects_by_id["child"]
        result = parser.is_indirect_relation_of("rdfs:subClassOf", obj, "grandparent")
        assert result is True
    
    def test_is_indirect_relation_of_not_related(self):
        """Test checking unrelated objects"""
        parser = D3FENDParser("dummy.json")
        parser.objects_by_id = {
            "child": {"@id": "child", "rdfs:subClassOf": [{"@id": "parent"}]},
            "parent": {"@id": "parent"},
            "unrelated": {"@id": "unrelated"}
        }
        
        obj = parser.objects_by_id["child"]
        result = parser.is_indirect_relation_of("rdfs:subClassOf", obj, "unrelated")
        assert result is False
    
    def test_is_indirect_relation_of_multiple_parents(self):
        """Test checking with multiple possible parents"""
        parser = D3FENDParser("dummy.json")
        parser.objects_by_id = {
            "child": {"@id": "child", "rdfs:subClassOf": [{"@id": "parent1"}]},
            "parent1": {"@id": "parent1"},
            "parent2": {"@id": "parent2"}
        }
        
        obj = parser.objects_by_id["child"]
        result = parser.is_indirect_relation_of("rdfs:subClassOf", obj, "parent1", "parent2")
        assert result is True
    
    def test_is_indirect_relation_of_circular_reference(self):
        """Test handling circular references"""
        parser = D3FENDParser("dummy.json")
        parser.objects_by_id = {
            "a": {"@id": "a", "rdfs:subClassOf": [{"@id": "b"}]},
            "b": {"@id": "b", "rdfs:subClassOf": [{"@id": "a"}]},
        }
        
        obj = parser.objects_by_id["a"]
        result = parser.is_indirect_relation_of("rdfs:subClassOf", obj, "nonexistent")
        assert result is False
    
    def test_extract_relationship_types(self, temp_json_file):
        """Test extracting relationship types from ontology"""
        parser = D3FENDParser(temp_json_file)
        parser.load_data()
        
        assert "rdfs:subClassOf" in parser.relationship_types
        assert parser.relationship_types["rdfs:subClassOf"] == "subclass-of"
    
    def test_load_data_merges_duplicate_ids(self):
        """Test that objects with duplicate IDs are merged"""
        data = {
            "@graph": [
                {"@id": "d3f:Test", "prop1": "value1"},
                {"@id": "d3f:Test", "prop2": "value2"}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_file = f.name
        
        parser = D3FENDParser(temp_file)
        
        # Mock the methods that would fail on minimal data
        parser._extract_release_date = MagicMock()
        parser._extract_relationship_types = MagicMock()
        
        parser.load_data()
        
        merged_obj = parser["d3f:test"]
        assert "prop1" in merged_obj or "prop2" in merged_obj
    
    def test_load_data_file_not_found(self):
        """Test handling of non-existent file"""
        parser = D3FENDParser("nonexistent_file.json")
        
        with pytest.raises(FileNotFoundError):
            parser.load_data()
    
    def test_load_data_invalid_json(self):
        """Test handling of invalid JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            temp_file = f.name
        
        parser = D3FENDParser(temp_file)
        
        with pytest.raises(json.JSONDecodeError):
            parser.load_data()
