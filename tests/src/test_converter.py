"""Tests for converter.py module"""
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch
from d3fend2stix.converter import D3FENDConverter
from d3fend2stix.parser import D3FENDParser
from stix2 import AttackPattern, Indicator, Relationship


class TestD3FENDConverter:
    """Tests for D3FENDConverter class"""
    
    @pytest.fixture
    def mock_parser(self):
        """Create a mock parser for testing"""
        parser = MagicMock(spec=D3FENDParser)
        parser.release_date = datetime(2024, 1, 1)
        parser.graph = []
        parser.objects_by_id = {}
        parser.relationship_types = {"rdfs:subClassOf": "subclass-of"}
        parser.root = {"@id": "http://d3fend.mitre.org/ontologies/d3fend.owl"}
        return parser
    
    @pytest.fixture
    def converter(self, mock_parser):
        """Create a converter instance for testing"""
        return D3FENDConverter(mock_parser)
    
    def test_converter_initialization(self, mock_parser):
        """Test converter initializes correctly"""
        converter = D3FENDConverter(mock_parser)
        assert converter.parser == mock_parser
        assert converter.stix_objects == {}
        assert converter.id_mapping == {}
        assert converter.created_artifacts == set()
    
    def test_create_technique_basic(self, converter):
        """Test creating a basic technique"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:d3fend-id": "D3-TT"
        }
        
        result = converter.create_technique(technique_obj)

        
        assert isinstance(result, AttackPattern)
        assert result.name == "Test Technique"
        assert result.description == "A test technique"
        assert "D3-TT" in str(result.external_references)
    
    def test_create_technique_with_synonyms(self, converter):
        """Test creating technique with synonyms/aliases"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:synonym": ["Synonym1", "Synonym2"]
        }
        
        result = converter.create_technique(technique_obj)
        
        assert hasattr(result, 'aliases')
        assert "Synonym1" in result.aliases
        assert "Synonym2" in result.aliases
    
    def test_create_technique_single_synonym(self, converter):
        """Test creating technique with single synonym"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:synonym": "SingleSynonym"
        }
        
        result = converter.create_technique(technique_obj)
        
        assert hasattr(result, 'aliases')
        assert "SingleSynonym" in result.aliases
    
    def test_create_tactic(self, converter):
        """Test creating a tactic"""
        tactic_obj = {
            "@id": "d3f:Detect",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection techniques"
        }
        
        result = converter.create_tactic(tactic_obj)
        
        assert result.name == "Detect"
        assert result.description == "Detection techniques"
        assert result.type == "x-d3fend-tactic"
    
    def test_create_matrix(self, converter):
        """Test creating matrix object"""
        tactic_ids = [
            "x-d3fend-tactic--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "x-d3fend-tactic--0ef0232d-97ee-47e5-8d83-f3aba6340fad"
        ]
        
        result = converter.create_matrix(tactic_ids)
        
        assert result.name == "D3fend"
        assert result.type == "x-mitre-matrix"
        assert len(result.tactic_refs) == 2
    
    def test_create_relationship(self, converter):
        """Test creating a relationship"""
        source = {"@id": "d3f:Source"}
        target = {"@id": "d3f:Target"}

        # Add mock STIX objects
        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [{"source_name": "mitre-d3fend", "url": "https://d3fend.mitre.org/technique/d3f:Source"}]
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [{"source_name": "mitre-d3fend", "url": "https://d3fend.mitre.org/technique/d3f:Target"}]
        }

        result = converter.create_relationship(source, target, "rdfs:subClassOf")
        assert isinstance(result, Relationship)
        assert result.source_ref == "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697"
        assert result.target_ref == "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad"
        assert result.relationship_type == "subclass-of"
    
    def test_create_artifact_indicator(self, converter):
        """Test creating artifact indicator"""
        artifact_obj = {
            "@id": "d3f:TestArtifact",
            "rdfs:label": "Test Artifact",
            "d3f:definition": "A test artifact"
        }
        
        result = converter.create_artifact_indicator(artifact_obj)
        
        assert isinstance(result, Indicator)
        assert result.name == "Test Artifact"
        assert result.pattern == "d3f:TestArtifact"
        assert result.pattern_type == "d3fend"
    
    def test_get_name_with_label(self, converter):
        """Test _get_name with rdfs:label"""
        obj = {"@id": "d3f:Test", "rdfs:label": "Test Label"}
        assert converter._get_name(obj) == "Test Label"
    
    def test_get_name_without_label(self, converter):
        """Test _get_name without rdfs:label"""
        obj = {"@id": "d3f:TestName"}
        assert converter._get_name(obj) == "TestName"
    
    def test_get_definition_with_definition(self, converter):
        """Test _get_definition with definition"""
        obj = {
            "@id": "d3f:Test",
            "d3f:definition": "Test definition"
        }
        assert converter._get_definition(obj) == "Test definition"
    
    def test_get_definition_with_kb_article(self, converter):
        """Test _get_definition with kb-article"""
        obj = {
            "@id": "d3f:Test",
            "d3f:definition": "Test definition",
            "d3f:kb-article": "Additional info"
        }
        result = converter._get_definition(obj)
        assert "Test definition" in result
        assert "Additional info" in result
    
    def test_extract_references_rdfs_see_also(self, converter, mock_parser):
        """Test extracting rdfs:seeAlso references"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:seeAlso": [{"@id": "http://example.com/resource"}]
        }
        
        result = converter._extract_references(obj)
        
        assert len(result) > 0
        assert any(ref.get("url") == "http://example.com/resource" for ref in result)
    
    def test_extract_references_kb_reference(self, converter, mock_parser):
        """Test extracting kb-reference"""
        ref_obj = {
            "@id": "d3f:KBRef1",
            "rdfs:label": "KB Reference",
            "d3f:kb-reference-title": "KB Title",
            "d3f:kb-abstract": "KB Abstract",
            "d3f:has-link": {"@value": "http://example.com/kb"}
        }
        
        mock_parser.__getitem__ = MagicMock(return_value=ref_obj)
        converter.parser = mock_parser
        
        obj = {
            "@id": "d3f:Test",
            "d3f:kb-reference": [{"@id": "d3f:KBRef1"}]
        }
        
        result = converter._extract_references(obj)
        
        assert len(result) > 0
        assert any(ref.get("source_name") == "KB Title" for ref in result)
    
    def test_extract_references_defined_by_http(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with HTTP URL"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:isDefinedBy": [{"@id": "http://example.com/defined"}]
        }
        
        result = converter._extract_references(obj)
        
        assert any(ref.get("url") == "http://example.com/defined" for ref in result)
    
    def test_extract_references_defined_by_dbr(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with DBpedia reference"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:isDefinedBy": ["dbr:Test_Resource"]
        }
        
        result = converter._extract_references(obj)
        
        assert any("dbpedia.org" in ref.get("url", "") for ref in result)
    
    def test_extract_references_defined_by_other(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with other reference"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:isDefinedBy": ["other:Reference"]
        }
        
        result = converter._extract_references(obj)
        
        assert any(ref.get("external_id") == "other:Reference" for ref in result)
    
    def test_convert_techniques(self, converter, mock_parser):
        """Test converting techniques"""
        technique = {
            "@id": "d3f:Technique1",
            "@type": "owl:Class",
            "rdfs:label": "Technique 1",
            "d3f:definition": "Test technique",
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}]
        }
        
        mock_parser.graph = [technique]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)
        
        result = converter._convert_techniques()
        
        assert len(result) > 0
        assert isinstance(result[0], AttackPattern)
    
    def test_convert_tactics(self, converter, mock_parser):
        """Test converting tactics"""
        tactic = {
            "@id": "d3f:Detect",
            "@type": "d3f:DefensiveTactic",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection"
        }
        
        mock_parser.get_objects_by_type = MagicMock(return_value=[tactic])
        
        result = converter._convert_tactics()
        
        assert len(result) == 1
        assert result[0].name == "Detect"
    
    def test_convert_matrix(self, converter, mock_parser):
        """Test converting matrix"""
        tactic_ids = ["x-d3fend-tactic--f4eba4fb-578d-4a04-9c32-b00141c0e697"]
        
        result = converter._convert_matrix(tactic_ids)
        
        assert result.name == "D3fend"
        assert len(converter.stix_objects) >= 1
    
    def test_convert_artifact_indicators(self, converter, mock_parser):
        """Test converting artifact indicators"""
        artifact = {
            "@id": "d3f:Artifact1",
            "@type": "owl:Class",
            "rdfs:label": "Artifact 1",
            "d3f:definition": "Test artifact",
            "rdfs:subClassOf": [{"@id": "d3f:Artifact"}]
        }
        
        mock_parser.graph = [artifact]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)
        
        result = converter._convert_artifact_indicators()
        
        assert len(result) > 0
        assert isinstance(result[0], Indicator)
    
    def test_convert_relationships(self, converter, mock_parser):
        """Test converting relationships"""
        source = {
            "@id": "d3f:Source",
            "rdfs:subClassOf": [{"@id": "d3f:Target"}]
        }
        target = {
            "@id": "d3f:Target",
            "@type": "owl:Class"
        }

        mock_parser.graph = [source]
        mock_parser.objects_by_id = {
            "d3f:target": target
        }
        mock_parser.__getitem__ = lambda self, key: mock_parser.objects_by_id.get(key.lower(), target)

        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [{"source_name": "test", "url": "https://example.com/source"}]
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [{"source_name": "test", "url": "https://example.com/target"}]
        }

        result = converter._convert_relationships()
        assert isinstance(result, list)
    
    def test_convert_relationships_with_owl_restriction(self, converter, mock_parser):
        """Test converting relationships with OWL restrictions"""
        source = {
            "@id": "d3f:Source",
            "rdfs:subClassOf": [{"@id": "d3f:Restriction"}]
        }
        restriction = {
            "@id": "d3f:Restriction",
            "@type": ["owl:Restriction"],
            "owl:onProperty": {"@id": "d3f:hasProperty"},
            "owl:someValuesFrom": {"@id": "d3f:Target"}
        }
        target = {
            "@id": "d3f:Target",
            "@type": "owl:Class"
        }
        
        mock_parser.graph = [source]
        mock_parser.objects_by_id = {
            "d3f:restriction": restriction,
            "d3f:target": target
        }
        mock_parser.__getitem__ = lambda self, key: mock_parser.objects_by_id.get(key.lower(), {})
        
        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [{"source_name": "test"}]
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [{"source_name": "test"}]
        }
        
        result = converter._convert_relationships()
        
        assert isinstance(result, list)
    
    def test_convert_full_workflow(self, converter, mock_parser):
        """Test full conversion workflow"""
        technique = {
            "@id": "d3f:Technique1",
            "@type": "owl:Class",
            "rdfs:label": "Technique 1",
            "d3f:definition": "Test",
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}]
        }
        tactic = {
            "@id": "d3f:Detect",
            "@type": "d3f:DefensiveTactic",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection"
        }
        
        mock_parser.graph = [technique, tactic]
        mock_parser.get_objects_by_type = MagicMock(return_value=[tactic])
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)
        
        result = converter.convert()
        
        # Should have at least default objects
        assert len(result) >= 2
        # Check we have some STIX objects returned
        assert isinstance(result, list)
    
    def test_get_techniques(self, converter, mock_parser):
        """Test _get_techniques method"""
        technique = {
            "@id": "d3f:Technique1",
            "@type": "owl:Class",
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}]
        }
        
        mock_parser.graph = [technique]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)
        
        techniques = list(converter._get_techniques())
        
        assert len(techniques) > 0
