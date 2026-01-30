"""Parse D3FEND JSON-LD data"""
import json
from typing import Dict, List, Any

from d3fend2stix.helper import ensure_list
from .loggings import logger
from datetime import datetime

def merge_dicts(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dictionaries, with b overriding a"""
    major, minor = a, b
    if len(b) > len(a):
        major, minor = b, a
    result = minor.copy()
    result.update(major)
    return result

class D3FENDParser:
    """Parser for D3FEND JSON-LD data"""
    
    def __init__(self, json_file_path: str):
        self.json_file_path = json_file_path
        self.data = None
        self.graph = []
        self.objects_by_id = {}
        self.release_date = None
        self.root = None
        self.version = None
        self.relationship_types = {
            'rdfs:subClassOf': 'subclass-of',
        }
        
    def load_data(self):
        """Load the D3FEND JSON file"""
        logger.info(f"Loading D3FEND data from {self.json_file_path}")
        with open(self.json_file_path, 'r') as f:
            self.data = json.load(f)
        
        # Extract the graph
        self.graph = self.data.get("@graph", [])
        
        # Build index by @id for quick lookup
        for obj in self.graph:
            self.add_object(obj)
        
        # Try to extract release date from version info
        self._extract_release_date()
        self._extract_relationship_types()
        
        logger.info(f"Loaded {len(self.graph)} objects from D3FEND data")

    def add_object(self, obj: Dict[str, Any]):
        """Add or update an object in the parser's index"""
        lower_id = obj.get("@id", "").lower()
        if lower_id in self.objects_by_id:
            self.objects_by_id[lower_id] = merge_dicts(obj, self.objects_by_id[lower_id])
        else:
            self.objects_by_id[lower_id] = obj

    def __getitem__(self, key):
        key = key.lower()
        return self.objects_by_id[key]
    
    def get(self, key, default=None):
        key = key.lower()
        return self.objects_by_id.get(key, default)

    def _extract_release_date(self):
        """Extract release date from D3FEND data"""
        self.root = self["http://d3fend.mitre.org/ontologies/d3fend.owl"]
        self.release_date = datetime.fromisoformat(self.root["d3f:release-date"]["@value"])
        self.version = self.root["owl:versionInfo"]
        self.title = self.root["dcterms:title"]

    def _extract_relationship_types(self):
        for obj in self.graph:
            onP = ensure_list(obj.get("owl:onProperty", []))
            for prop in onP:
                prop_id = prop["@id"]
                if prop_id not in self.objects_by_id:
                    continue
                prop_decl = self.objects_by_id[prop_id]
                prop_type = prop_decl.get("@type", [])
                if self.is_indirect_relation_of("rdfs:subPropertyOf", prop_decl, "d3f:may-be-associated-with"):
                    self.relationship_types[prop_id] = prop_id.split(":")[-1]

    def get_objects_by_type(self, type_value: str) -> List[Dict[str, Any]]:
        """Get all objects with a specific @type"""
        results = []
        for obj in self.graph:
            types = ensure_list(obj.get("@type", []))
            if type_value in types:
                results.append(obj)
        return results
    
    def is_indirect_relation_of(self, rel_type, obj: Dict[str, Any], *parent_id: str) -> bool:
        """Check if an object is an indirect subclass of a given parent(s)"""
        visited = set()
        to_visit = [obj]
        parent_id = parent_id
        
        while to_visit:
            current = to_visit.pop()
            if current["@id"] in visited:
                continue
            visited.add(current["@id"])
            
            subclasses = ensure_list(current.get(rel_type, []))
            for subclass in subclasses:
                subclass_id = subclass["@id"]
                if subclass_id in parent_id:
                    return True
                subclass_obj = self[subclass_id]
                if subclass_obj:
                    to_visit.append(subclass_obj)
        
        return False
    
    def get_inherited_property(self, obj: Dict[str, Any], property_name: str) -> Any:
        """Get a property value, checking superclasses if not found"""
        if property_name in obj:
            return ensure_list(obj[property_name])
        
        # Check superclasses
        superclasses = ensure_list(obj.get("rdfs:subClassOf", []))
        for superclass_ref in superclasses:
            superclass_id = superclass_ref["@id"]
            superclass_obj = self.get(superclass_id.lower())
            if superclass_obj:
                value = self.get_inherited_property(superclass_obj, property_name)
                if value:
                    return value
        return []