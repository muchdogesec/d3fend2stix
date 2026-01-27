"""Pytest configuration and fixtures"""
import pytest
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from d3fend2stix.config import DEFAULT_CONFIG as config


@pytest.fixture
def sample_d3fend_data():
    """Minimal D3FEND data for testing"""
    return {
        "@context": {},
        "@graph": [
            {
                "@id": "http://d3fend.mitre.org/ontologies/d3fend.owl",
                "@type": ["owl:Ontology"],
                "dcterms:title": "D3FEND",
                "owl:versionInfo": "1.3.0",
                "d3f:release-date": {"@value": "2024-01-15T00:00:00"}
            },
            {
                "@id": "d3f:DefensiveTechnique",
                "@type": ["owl:Class"],
                "rdfs:label": "Defensive Technique",
                "d3f:definition": "Base class for defensive techniques"
            },
            {
                "@id": "d3f:DefensiveTactic",
                "@type": ["owl:Class", "d3f:DefensiveTactic"],
                "rdfs:label": "Defensive Tactic",
                "d3f:definition": "Base class for defensive tactics"
            },
            {
                "@id": "d3f:Detect",
                "@type": ["owl:Class", "d3f:DefensiveTactic"],
                "rdfs:label": "Detect",
                "d3f:definition": "Detect adversary activities",
                "rdfs:subClassOf": [{"@id": "d3f:DefensiveTactic"}]
            },
            {
                "@id": "d3f:FileAnalysis",
                "@type": ["owl:Class"],
                "rdfs:label": "File Analysis",
                "d3f:definition": "Analysis of file artifacts",
                "d3f:d3fend-id": "D3-FA",
                "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
                "rdfs:seeAlso": [{"@id": "https://example.com/ref1"}],
                "d3f:synonym": ["File Examination"]
            },
            {
                "@id": "d3f:may-be-associated-with",
                "@type": ["owl:ObjectProperty"],
                "rdfs:label": "may be associated with"
            },
            {
                "@id": "d3f:analyzes",
                "@type": ["owl:ObjectProperty"],
                "rdfs:label": "analyzes",
                "rdfs:subPropertyOf": [{"@id": "d3f:may-be-associated-with"}]
            },
            {
                "@id": "d3f:DigitalArtifact",
                "@type": ["owl:Class"],
                "rdfs:label": "Digital Artifact",
                "d3f:definition": "A digital artifact"
            }
        ]
    }


@pytest.fixture
def sample_technique_obj():
    """Sample technique object"""
    return {
        "@id": "d3f:FileAnalysis",
        "@type": ["owl:Class"],
        "rdfs:label": "File Analysis",
        "d3f:definition": "Analysis of file artifacts",
        "d3f:d3fend-id": "D3-FA",
        "rdfs:subClassOf": [{"@id": "d3f:DefensiveTechnique"}],
        "rdfs:seeAlso": [{"@id": "https://example.com/ref1"}],
        "d3f:synonym": ["File Examination", "File Inspection"]
    }


@pytest.fixture
def sample_tactic_obj():
    """Sample tactic object"""
    return {
        "@id": "d3f:Detect",
        "@type": ["owl:Class", "d3f:DefensiveTactic"],
        "rdfs:label": "Detect",
        "d3f:definition": "Detect adversary activities"
    }


@pytest.fixture
def sample_artifact_obj():
    """Sample artifact object"""
    return {
        "@id": "d3f:File",
        "@type": ["owl:Class"],
        "rdfs:label": "File",
        "d3f:definition": "A computer file"
    }


@pytest.fixture
def temp_d3fend_file(tmp_path, sample_d3fend_data):
    """Create a temporary D3FEND JSON file"""
    file_path = tmp_path / "test_d3fend.json"
    with open(file_path, 'w') as f:
        json.dump(sample_d3fend_data, f)
    return str(file_path)


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary output directories"""
    stix_objects = tmp_path / "stix2_objects"
    stix_bundles = tmp_path / "stix2_bundles"
    stix_objects.mkdir()
    stix_bundles.mkdir()
    return {
        "objects": str(stix_objects),
        "bundles": str(stix_bundles)
    }


@pytest.fixture
def mock_config(monkeypatch, temp_output_dir, temp_d3fend_file):
    """Mock configuration for testing"""
    monkeypatch.setattr(config, "d3fend_json_file", temp_d3fend_file)
    monkeypatch.setattr(config, "stix2_objects_folder", temp_output_dir["objects"])
    monkeypatch.setattr(config, "stix2_bundles_folder", temp_output_dir["bundles"])
    return config
