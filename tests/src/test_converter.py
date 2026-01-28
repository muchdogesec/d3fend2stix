"""Tests for converter.py module"""

import json
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
        parser.root = {
            "@id": "http://d3fend.mitre.org/ontologies/d3fend.owl",
            "@type": "owl:Ontology",
            "d3f:release-date": {
                "@type": "xsd:dateTime",
                "@value": "2025-12-16T00:12:00+00:00",
            },
            "dcterms:description": "Sample description",
            "dcterms:license": "MIT",
            "dcterms:title": "D3FEND Test Ontology",
            "owl:versionIRI": {
                "@id": "http://d3fend.mitre.org/ontologies/d3fend/1.3.0/d3fend.owl"
            },
            "owl:versionInfo": "1.3.0",
            "rdfs:comment": "Use of the D3FEND Knowledge Graph, and the associated references from this ontology are subject to the Terms of Use. D3FEND is funded by the National Security Agency (NSA) Cybersecurity Directorate and managed by the National Security Engineering Center (NSEC) which is operated by The MITRE Corporation. D3FEND™ and the D3FEND logo are trademarks of The MITRE Corporation. This software was produced for the U.S. Government under Basic Contract No. W56KGU-18-D0004, and is subject to the Rights in Noncommercial Computer Software and Noncommercial Computer Software Documentation Clause 252.227-7014 (FEB 2012) Copyright 2022 The MITRE Corporation.",
        }
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

    def test_create_technique_basic(self, converter_with_tactics):
        """Test creating a basic technique"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:d3fend-id": "D3-TT",
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert isinstance(result, AttackPattern)
        assert result.name == "Test Technique"
        assert result.description == "A test technique"
        assert "D3-TT" in str(result.external_references)

    def test_create_technique_with_synonyms(self, converter_with_tactics):
        """Test creating technique with synonyms/aliases"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:synonym": ["Synonym1", "Synonym2"],
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "aliases")
        assert "Synonym1" in result.aliases
        assert "Synonym2" in result.aliases

    def test_create_technique_single_synonym(self, converter_with_tactics):
        """Test creating technique with single synonym"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:synonym": "SingleSynonym",
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "aliases")
        assert "SingleSynonym" in result.aliases

    def test_create_technique_with_kill_chain_phases(self, converter_with_tactics):
        """Test creating technique with kill chain phases"""
        technique_obj = {
            "@id": "d3f:TestTechnique",
            "rdfs:label": "Test Technique",
            "d3f:definition": "A test technique",
            "d3f:enables": [{"@id": "D3-Tactic-1"}],
        }
        converter_with_tactics.parser.get_inherited_property.return_value = [
            {"@id": "D3-Tactic-1"}
        ]

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "kill_chain_phases")
        assert [dict(k) for k in result.kill_chain_phases] == [
            {"kill_chain_name": "d3fend", "phase_name": "detect"}
        ]


        converter_with_tactics.parser.get_inherited_property.return_value = [
            {"@id": "D3-Tactic-1"}, {"@id": "D3-Tactic-2"}
        ]
        result = converter_with_tactics.create_technique(technique_obj)
        assert [dict(k) for k in result.kill_chain_phases] == [
            {"kill_chain_name": "d3fend", "phase_name": "detect"},
            {"kill_chain_name": "d3fend", "phase_name": "prevent"},
        ]

    def test_create_technique_is_parent_technique(self, converter_with_tactics):
        """Test that parent technique has x_mitre_is_subtechnique=False"""
        # Parent technique - has d3f:DefensiveTechnique in rdfs:subClassOf
        technique_obj = {
            "@id": "d3f:ParentTechnique",
            "rdfs:label": "Parent Technique",
            "d3f:definition": "A parent technique",
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "x_mitre_is_subtechnique")
        assert result.x_mitre_is_subtechnique is False

    def test_create_technique_is_subtechnique(self, converter_with_tactics):
        """Test that sub-technique has x_mitre_is_subtechnique=True"""
        # Sub-technique - does NOT have d3f:DefensiveTechnique in rdfs:subClassOf
        technique_obj = {
            "@id": "d3f:SubTechnique",
            "rdfs:label": "Sub Technique",
            "d3f:definition": "A sub-technique",
            "rdfs:subClassOf": [{"@id": "d3f:SomeParentTechnique"}],
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "x_mitre_is_subtechnique")
        assert result.x_mitre_is_subtechnique is True

    def test_create_technique_multiple_subclasses_with_defensive(self, converter_with_tactics):
        """Test technique with multiple subclasses including DefensiveTechnique"""
        technique_obj = {
            "@id": "d3f:MultiSubTechnique",
            "rdfs:label": "Multi Sub Technique",
            "d3f:definition": "A technique with multiple subclasses",
            "rdfs:subClassOf": [
                {"@id": "d3f:SomeOtherClass"},
                {"@id": "d3f:DefensiveTechnique"},
                {"@id": "d3f:AnotherClass"}
            ],
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "x_mitre_is_subtechnique")
        assert result.x_mitre_is_subtechnique is False

    def test_create_technique_multiple_subclasses_without_defensive(self, converter_with_tactics):
        """Test technique with multiple subclasses not including DefensiveTechnique"""
        technique_obj = {
            "@id": "d3f:MultiSubTechnique2",
            "rdfs:label": "Multi Sub Technique 2",
            "d3f:definition": "Another technique with multiple subclasses",
            "rdfs:subClassOf": [
                {"@id": "d3f:ParentTechnique1"},
                {"@id": "d3f:ParentTechnique2"}
            ],
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "x_mitre_is_subtechnique")
        assert result.x_mitre_is_subtechnique is True

    def test_create_technique_no_subclassof(self, converter_with_tactics):
        """Test technique without rdfs:subClassOf property"""
        technique_obj = {
            "@id": "d3f:StandaloneTechnique",
            "rdfs:label": "Standalone Technique",
            "d3f:definition": "A technique without subClassOf",
        }

        result = converter_with_tactics.create_technique(technique_obj)

        assert hasattr(result, "x_mitre_is_subtechnique")
        # Should be True since d3f:DefensiveTechnique is NOT in the list (empty list)
        assert result.x_mitre_is_subtechnique is True


    def test_create_tactic(self, converter):
        """Test creating a tactic"""
        tactic_obj = {
            "@id": "d3f:Detect",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection techniques",
        }

        result = converter.create_tactic(tactic_obj)

        assert result.name == "Detect"
        assert result.description == "Detection techniques"
        assert result.type == "x-mitre-tactic"

    def test_create_matrix(self, converter):
        """Test creating matrix object"""
        tactic_ids = [
            "x-mitre-tactic--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "x-mitre-tactic--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
        ]

        result = converter.create_matrix(tactic_ids)

        assert json.loads(result.serialize()) == {
            "type": "x-mitre-matrix",
            "spec_version": "2.1",
            "id": "x-mitre-matrix--00c1d7a9-ae23-585c-b3d1-a1295765de46",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "D3FEND Test Ontology",
            "description": "Sample description",
            "tactic_refs": tactic_ids,
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/",
                    "external_id": "mitre-d3fend",
                },
                {"source_name": "license", "external_id": "MIT"},
                {
                    "source_name": "version",
                    "url": "http://d3fend.mitre.org/ontologies/d3fend/1.3.0/d3fend.owl",
                    "external_id": "1.3.0",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22",
            ],
        }
        assert result.type == "x-mitre-matrix"
        assert len(result.tactic_refs) == 2

    def test_create_relationship(self, converter):
        """Test creating a relationship"""
        source = {"@id": "d3f:Source"}
        target = {"@id": "d3f:Target"}

        # Add mock STIX objects
        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:Source",
                }
            ],
            "type": "attack-pattern",
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:Target",
                }
            ],
            "type": "attack-pattern",
        }
        converter.stix_objects["d3f:SecondTarget"] = {
            "id": "indicator--12345678-1234-5678-1234-567812345678",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/random/d3f:SecondTarget",
                }
            ],
            "type": "indicator",
        }

        result = converter.create_relationship(source, target, "rdfs:subClassOf")
        assert isinstance(result, Relationship)
        assert json.loads(result.serialize()) == {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--3a7ceb7d-fc94-5f5b-a026-c749fb28d283",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "relationship_type": "subtechnique-of",
            "description": "Source is a sub-class of Target",
            "source_ref": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "target_ref": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:Source",
                },
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:Target",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22",
            ],
        }

    def test_create_relationship_subtechniques(self, converter):
        """Test creating relationship for sub-techniques"""
        source = {"@id": "d3f:SubTechnique"}
        target = {"@id": "d3f:ParentTechnique"}

        # Add mock STIX objects
        converter.stix_objects["d3f:SubTechnique"] = {
            "id": "attack-pattern--4baf2433-6993-4272-bac9-f717941bc7dc",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:SubTechnique",
                }
            ],
            "type": "attack-pattern",
        }
        converter.stix_objects["d3f:ParentTechnique"] = {
            "id": "attack-pattern--4847f5c8-2e29-4cfe-9692-9198adf23b4e",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:ParentTechnique",
                }
            ],
            "type": "attack-pattern",
        }

        result = converter.create_relationship(source, target, "rdfs:subClassOf")
        assert json.loads(result.serialize()) == {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--e07e4b28-7856-55ef-8364-9824173b28ae",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "relationship_type": "subtechnique-of",
            "description": "SubTechnique is a sub-class of ParentTechnique",
            "source_ref": "attack-pattern--4baf2433-6993-4272-bac9-f717941bc7dc",
            "target_ref": "attack-pattern--4847f5c8-2e29-4cfe-9692-9198adf23b4e",
            "external_references": [
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:SubTechnique",
                },
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/technique/d3f:ParentTechnique",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22",
            ],
        }

    def test_create_artifact_indicator(self, converter):
        """Test creating artifact indicator"""
        artifact_obj = {
            "@id": "d3f:TestArtifact",
            "rdfs:label": "Test Artifact",
            "d3f:definition": "A test artifact",
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
        obj = {"@id": "d3f:Test", "d3f:definition": "Test definition"}
        assert converter._get_definition(obj) == "Test definition"

    def test_get_definition_with_kb_article(self, converter):
        """Test _get_definition with kb-article"""
        obj = {
            "@id": "d3f:Test",
            "d3f:definition": "Test definition",
            "d3f:kb-article": "Additional info",
        }
        result = converter._get_definition(obj)
        assert "Test definition" in result
        assert "Additional info" in result

    def test_extract_references_rdfs_see_also(self, converter, mock_parser):
        """Test extracting rdfs:seeAlso references"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:seeAlso": [{"@id": "http://example.com/resource"}],
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
            "d3f:has-link": {"@value": "http://example.com/kb"},
        }

        mock_parser.__getitem__ = MagicMock(return_value=ref_obj)
        converter.parser = mock_parser

        obj = {"@id": "d3f:Test", "d3f:kb-reference": [{"@id": "d3f:KBRef1"}]}

        result = converter._extract_references(obj)

        assert len(result) > 0
        assert any(ref.get("source_name") == "KB Title" for ref in result)

    def test_extract_references_defined_by_http(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with HTTP URL"""
        obj = {
            "@id": "d3f:Test",
            "rdfs:isDefinedBy": [{"@id": "http://example.com/defined"}],
        }

        result = converter._extract_references(obj)

        assert any(ref.get("url") == "http://example.com/defined" for ref in result)

    def test_extract_references_defined_by_dbr(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with DBpedia reference"""
        obj = {"@id": "d3f:Test", "rdfs:isDefinedBy": ["dbr:Test_Resource"]}

        result = converter._extract_references(obj)

        assert any("dbpedia.org" in ref.get("url", "") for ref in result)

    def test_extract_references_defined_by_other(self, converter, mock_parser):
        """Test extracting rdfs:isDefinedBy with other reference"""
        obj = {"@id": "d3f:Test", "rdfs:isDefinedBy": ["other:Reference"]}

        result = converter._extract_references(obj)

        assert any(ref.get("external_id") == "other:Reference" for ref in result)

    @pytest.fixture
    def converter_with_tactics(self, converter):
        """Fixture to set up converter with mock tactics"""
        tactic1 = {
            "x_mitre_shortname": "detect",
            "external_references": [
                {"source_name": "mitre-d3fend", "external_id": "D3-Tactic-1"}
            ],
        }
        tactic2 = {
            "x_mitre_shortname": "prevent",
            "external_references": [
                {"source_name": "mitre-d3fend", "external_id": "D3-Tactic-2"}
            ],
        }
        converter.tactics = [tactic1, tactic2]
        return converter

    def test_convert_techniques(self, converter_with_tactics, mock_parser):
        """Test converting techniques"""
        technique = {
            "@id": "d3f:Technique1",
            "@type": "owl:Class",
            "rdfs:label": "Technique 1",
            "d3f:definition": "Test technique",
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
        }

        mock_parser.graph = [technique]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)

        result = converter_with_tactics._convert_techniques()

        assert len(result) > 0
        assert isinstance(result[0], AttackPattern)

    def test_convert_tactics(self, converter, mock_parser):
        """Test converting tactics"""
        tactic = {
            "@id": "d3f:Detect",
            "@type": "d3f:DefensiveTactic",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection",
        }

        mock_parser.get_objects_by_type = MagicMock(return_value=[tactic])

        result = converter._convert_tactics()

        assert len(result) == 1
        assert result[0].name == "Detect"

    def test_convert_matrix(self, converter, mock_parser):
        """Test converting matrix"""
        tactic_ids = ["x-mitre-tactic--f4eba4fb-578d-4a04-9c32-b00141c0e697"]

        result = converter._convert_matrix(tactic_ids)
        assert result.name == "D3FEND Test Ontology"
        assert result.tactic_refs == tactic_ids
        assert len(converter.stix_objects) >= 1

    def test_convert_artifact_indicators(self, converter, mock_parser):
        """Test converting artifact indicators"""
        artifact = {
            "@id": "d3f:Artifact1",
            "@type": "owl:Class",
            "rdfs:label": "Artifact 1",
            "d3f:definition": "Test artifact",
            "rdfs:subClassOf": [{"@id": "d3f:Artifact"}],
        }

        mock_parser.graph = [artifact]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)

        result = converter._convert_artifact_indicators()

        assert len(result) > 0
        assert isinstance(result[0], Indicator)

    def test_convert_relationships(self, converter, mock_parser):
        """Test converting relationships"""
        source = {"@id": "d3f:Source", "rdfs:subClassOf": [{"@id": "d3f:Target"}]}
        target = {"@id": "d3f:Target", "@type": "owl:Class"}

        mock_parser.graph = [source]
        mock_parser.objects_by_id = {"d3f:target": target}
        mock_parser.__getitem__ = lambda self, key: mock_parser.objects_by_id.get(
            key.lower(), target
        )

        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [
                {"source_name": "test", "url": "https://example.com/source"}
            ],
            "type": "attack-pattern",
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [
                {"source_name": "test", "url": "https://example.com/target"}
            ],
            "type": "attack-pattern",
        }

        result = converter._convert_relationships()
        assert isinstance(result, list)

    def test_convert_relationships_with_owl_restriction(self, converter, mock_parser):
        """Test converting relationships with OWL restrictions"""
        source = {"@id": "d3f:Source", "rdfs:subClassOf": [{"@id": "d3f:Restriction"}]}
        restriction = {
            "@id": "d3f:Restriction",
            "@type": ["owl:Restriction"],
            "owl:onProperty": {"@id": "d3f:hasProperty"},
            "owl:someValuesFrom": {"@id": "d3f:Target"},
        }
        target = {"@id": "d3f:Target", "@type": "owl:Class"}

        mock_parser.graph = [source]
        mock_parser.objects_by_id = {
            "d3f:restriction": restriction,
            "d3f:target": target,
        }
        mock_parser.__getitem__ = lambda self, key: mock_parser.objects_by_id.get(
            key.lower(), {}
        )

        converter.stix_objects["d3f:Source"] = {
            "id": "attack-pattern--f4eba4fb-578d-4a04-9c32-b00141c0e697",
            "external_references": [{"source_name": "test"}],
        }
        converter.stix_objects["d3f:Target"] = {
            "id": "attack-pattern--0ef0232d-97ee-47e5-8d83-f3aba6340fad",
            "external_references": [{"source_name": "test"}],
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
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
        }
        tactic = {
            "@id": "d3f:Detect",
            "@type": "d3f:DefensiveTactic",
            "rdfs:label": "Detect",
            "d3f:definition": "Detection",
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
            "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
        }

        mock_parser.graph = [technique]
        mock_parser.is_indirect_relation_of = MagicMock(return_value=True)

        techniques = list(converter._get_techniques())

        assert len(techniques) > 0
