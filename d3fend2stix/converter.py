"""Main conversion logic for d3fend2stix"""

from collections import defaultdict
import re
from typing import List, Dict, Any, Tuple

from d3fend2stix.stix_definitions import D3FENDTactic, Matrix
from .parser import D3FENDParser

# from .stix_objects import (
#     create_matrix, create_tactic, create_technique,
#     create_artifact_indicator, create_relationship
# )
from .config import DEFAULT_CONFIG as config
from .helper import ensure_list, extract_id_from_uri, generate_stix_id, safe_get, stix_as_dict
from .loggings import logger
from stix2 import CourseOfAction, Indicator, Relationship, Bundle, Artifact


class D3FENDConverter:
    """Convert D3FEND data to STIX objects"""

    def __init__(self, parser: D3FENDParser):
        self.parser = parser
        self.stix_objects: dict[str, dict] = {}
        self.id_mapping = {}  # Maps D3FEND IDs to STIX IDs
        self.created_artifacts = set()  # Track created artifact indicators
        self.tactic_technique_map = defaultdict(list)  # Map tactic IDs to their techniques
        self.other_relationships = []  # Store other relationships

    def convert(self) -> List[Any]:
        """
        Main conversion method
        Returns list of all STIX objects
        """
        objects = []
        logger.info("Starting D3FEND to STIX conversion")

        # Add default objects (identity and marking definition)
        objects.extend(config.default_objects)
        logger.info(f"Added {len(config.default_objects)} default objects")
        # Step 1: Create tactics
        tactics = self._convert_tactics()
        logger.info(f"Created {len(tactics)} tactic objects")
        self.tactics = tactics

        # Step 2: Create techniques (all levels)
        techniques = self._convert_techniques()
        logger.info(f"Created {len(techniques)} technique objects")

        tech_tactic_relationships = self._add_tactic_technique_relationships()
        logger.info(f"Created {len(tech_tactic_relationships)} technique-tactic relationships")

        # Step 3: Create matrix with tactic references
        matrix = self._convert_matrix([t.id for t in tactics])
        logger.info("Created matrix object")

        # Step 4: Create artifacts with tactic references
        artifacts = self._convert_artifact_indicators()
        logger.info("Created artifacts object")

        # Step 5: Create relationships between objects
        relationships = self._convert_relationships()
        logger.info(f"Created {len(relationships)} relationship objects")

        # Collect all objects
        objects.extend(self.stix_objects.values())
        logger.info(f"Total STIX objects created: {len(self.stix_objects)}")
        return objects

    def _convert_techniques(self) -> List[Any]:
        """Convert D3FEND techniques to STIX techniques"""
        techniques = []
        unparsed_technique_objs = list(self._get_techniques())

        for tech_obj in unparsed_technique_objs:
            stix_tech = self.create_technique(tech_obj)
            self.stix_objects[tech_obj["@id"]] = stix_tech
            techniques.append(stix_tech)
        return techniques

    def _get_techniques(self):
        for obj in self.parser.graph:
            if self.parser.is_indirect_relation_of("rdfs:subClassOf", obj, "d3f:DefensiveTechnique"):
                yield obj

    def _convert_tactics(self) -> List[Any]:
        """Convert all D3FEND tactics"""
        tactics = []
        for tactic_obj in sorted(self.parser.get_objects_by_type("d3f:DefensiveTactic"), key=lambda x: x["d3f:display-order"]):
            stix_tactic = self.create_tactic(tactic_obj)
            self.stix_objects[tactic_obj["@id"]] = stix_tactic
            tactics.append(stix_tactic)
        return tactics

    def _convert_matrix(self, tactic_ids: List[str]) -> Any:
        """Convert the D3FEND matrix"""
        matrix = self.create_matrix(tactic_ids)
        self.stix_objects[self.parser.root["@id"]] = matrix
        return matrix

    def create_technique(self, technique_obj: Dict[str, Any]) -> CourseOfAction:
        """Create an Attack Pattern (Technique) STIX object"""
        technique_id_raw = technique_obj["@id"]
        technique_id = generate_stix_id("course-of-action", technique_id_raw)

        # Build external references
        external_refs = [
            {
                "source_name": "mitre-d3fend",
                "url": f"https://d3fend.mitre.org/technique/{technique_id_raw}",
                "external_id": self.get_d3fend_id(technique_obj),
            },
            *self._extract_references(technique_obj)
        ]

        # Get aliases/synonyms
        aliases = []
        synonym = technique_obj.get("d3f:synonym")
        if synonym:
            synonyms = synonym if isinstance(synonym, list) else [synonym]
            aliases.extend(synonyms)

        tactic_external_refs = self._parse_tech_tactics(technique_obj)

        course_of_action = CourseOfAction(
            id=technique_id,
            created=self.parser.release_date,
            modified=self.parser.release_date,
            created_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            name=self._get_name(technique_obj),
            description=self._get_definition(technique_obj),
            x_mitre_is_subtechnique={"@id":"d3f:DefensiveTechnique"} not in ensure_list(technique_obj.get("rdfs:subClassOf")),
            external_references=external_refs + tactic_external_refs,
            object_marking_refs=config.marking_refs,
            **({"x_aliases": aliases} if aliases else {}),
            x_mitre_domains=["d3fend"],
            x_mitre_deprecated=False,
            x_mitre_version="0.1",
            x_mitre_modified_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            x_mitre_platforms=["-"],
            x_mitre_attack_spec_version="3.3.0",
            allow_custom=True,
        )

        return course_of_action

    def _parse_tech_tactics(self, technique: Dict[str, Any]) -> List[Dict[str, str]]:
        """Parse kill chain phases from a technique object"""
        tactic_external_refs = []
        all_properties = [d['@id'] for d in self.parser.get_inherited_property(technique, "d3f:enables")]

        for tactic in self.tactics:
            tactic_id_raw = tactic['external_references'][0]['external_id']
            if tactic_id_raw in all_properties:
                self.tactic_technique_map[tactic_id_raw].append(technique['@id'])
                ref = stix_as_dict(tactic['external_references'][0]).copy()
                ref['description'] = "This technique enables the tactic " + tactic['name']
                tactic_external_refs.append(ref)
        return tactic_external_refs

    def _extract_references(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract external references from a D3FEND object"""
        references = []
        see_also_list = ensure_list(obj.get("rdfs:seeAlso"))
        for ref in see_also_list:
            ref_id = ref.get("@id") if isinstance(ref, dict) else ref
            if ref_id:
                references.append({
                    "source_name": "rdfs-seeAlso",
                    "url": self.sanitize_url(ref_id)[0],
                })
        # Add kb-reference entries
        kb_refs = ensure_list(obj.get("d3f:kb-reference"))
        for ref in kb_refs:
            ref_obj = self.parser[ref["@id"]]
            ref_entry = {
                "source_name": ref_obj.get("d3f:kb-reference-title", ref_obj["rdfs:label"])
            }
            if "d3f:kb-abstract" in ref_obj:
                ref_entry["description"] = ref_obj["d3f:kb-abstract"]
            if "d3f:has-link" in ref_obj:
                ref_entry["url"] = ref_obj["d3f:has-link"]["@value"]
            if len(ref_entry) > 1:
                references.append(ref_entry)

        # add defined-by reference
        defined_by_refs = ensure_list(obj.get("rdfs:isDefinedBy"))
        for ref in defined_by_refs:
            ref_id = ref['@id'] if isinstance(ref, dict) else ref
            sanitized_url, is_valid = self.sanitize_url(ref_id)
            if is_valid:
                references.append({
                    "source_name": "rdfs-defined-by",
                    "url": sanitized_url,
                })
            else:
                references.append({
                    "source_name": "rdfs-defined-by",
                    "external_id": ref_id,
                })

        return references

    @staticmethod
    def sanitize_url(url: str) -> Tuple[str, bool]:
        if url.startswith("http://") or url.startswith("https://"):
            return url, True
        elif url.startswith("dbr:"):
            dbr_id = url[4:]
            return f"http://dbpedia.org/resource/{dbr_id}", True
        return url, False

    def create_tactic(self, tactic_obj: Dict[str, Any]) -> Any:
        """Create a D3FEND Tactic STIX object"""
        tactic_id_raw = tactic_obj["@id"]
        tactic_id = generate_stix_id("x-mitre-tactic", tactic_id_raw)
        mitre_short_name = tactic_id_raw.split(":")[-1].lower()

        tactic = D3FENDTactic(
            id=tactic_id,
            created=self.parser.release_date,
            modified=self.parser.release_date,
            created_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            name=self._get_name(tactic_obj),
            x_mitre_shortname=mitre_short_name,
            description=self._get_definition(tactic_obj),
            external_references=[
                {
                    "source_name": "mitre-d3fend",
                    "url": f"https://d3fend.mitre.org/tactic/{tactic_id_raw}",
                    "external_id": self.get_d3fend_id(tactic_obj),
                }
            ],
            object_marking_refs=config.marking_refs,
            x_mitre_domains=["d3fend"],
            x_mitre_deprecated=False,
            x_mitre_version="0.1",
            x_mitre_modified_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            x_mitre_attack_spec_version="3.3.0",
            allow_custom=True,
        )

        return tactic

    def create_matrix(self, tactic_ids: List[str]) -> Any:
        """Create a D3FEND Matrix STIX object"""
        """Create the D3FEND Matrix object"""
        matrix_id = generate_stix_id("x-mitre-matrix", "mitre-d3fend")

        matrix = Matrix(
            id=matrix_id,
            created=self.parser.release_date,
            modified=self.parser.release_date,
            created_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            name=self.parser.root['dcterms:title'],
            description=self.parser.root['dcterms:description'],
            tactic_refs=tactic_ids,
            external_references=[
                {
                    "source_name": "mitre-d3fend",
                    "url": "https://d3fend.mitre.org/",
                    "external_id": "mitre-d3fend",
                },
                {
                    "source_name": "license",
                    "external_id": self.parser.root["dcterms:license"],
                },
                {
                    "source_name": "version",
                    "url": self.parser.root["owl:versionIRI"]["@id"],
                    "external_id": self.parser.root["owl:versionInfo"],
                }

            ],
            object_marking_refs=config.marking_refs,
            x_mitre_domains=["d3fend"],
            x_mitre_deprecated=False,
            x_mitre_version="0.1",
            x_mitre_modified_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            x_mitre_attack_spec_version="3.3.0",
            allow_custom=True,
        )

        return matrix

    @staticmethod
    def _get_name(raw: dict):
        """Extract name from raw object"""
        return raw.get("rdfs:label", extract_id_from_uri(raw["@id"]))

    @staticmethod
    def _get_definition(raw: dict):
        """Extract definition from raw object"""
        definition = raw.get("d3f:definition", "")
        kb_article = raw.get("d3f:kb-article", "")

        # Combine definition and kb-article for description
        description = definition
        if kb_article:
            description = f"{definition}\n\n{kb_article}"
        return description

    def _add_tactic_technique_relationships(self):
        """Add relationships between tactics and techniques based on enables property"""
        relationships = []
        for tactic_id, technique_ids in self.tactic_technique_map.items():
            for tech_id in technique_ids:
                if tech_id not in self.stix_objects or tactic_id not in self.stix_objects:
                    continue
                relationship = self.create_relationship(
                    self.parser[tech_id],
                    self.parser[tactic_id],
                    "d3f:enables"
                )
                if relationship:
                    self.stix_objects[relationship.id] = relationship
                    relationships.append(relationship)
        return relationships

    def _convert_relationships(self) -> List[Any]:
        """Convert relationships between D3FEND objects"""
        relationships = []
        for graph_obj in self.parser.graph:
            rel_keys = set(graph_obj.keys()) & set(self.parser.relationship_types)
            for rel_key in rel_keys:
                if rel_key == 'd3f:enables' and self.parser.is_indirect_relation_of("rdfs:subClassOf", graph_obj, "d3f:DefensiveTechnique"):
                    # Skip enables relationships as they are handled via tactic references
                    continue
                targets = ensure_list(graph_obj[rel_key])
                for target_id in targets:
                    relationship_type = rel_key
                    target_obj = self.parser[target_id["@id"]]

                    if target_obj['@id'] not in self.stix_objects or graph_obj['@id'] not in self.stix_objects:
                        if relationship_type != 'rdfs:subClassOf':
                            self.other_relationships.append(
                                dict(
                                    source=self.get_d3fend_id(graph_obj),
                                    target=self.get_d3fend_id(target_obj),
                                    type=relationship_type,
                                    description=self._get_relationship_description(
                                        relationship_type, graph_obj, target_obj
                                    ),
                                )
                            )
                        continue
                    stix_rel = self.create_relationship(graph_obj, target_obj, relationship_type)
                    if stix_rel:
                        self.stix_objects[stix_rel.id] = stix_rel
                        relationships.append(stix_rel)
        return relationships

    def create_relationship(self, source, target, rel_type) -> Any:
        """Create a STIX Relationship object"""
        source_stix = self.stix_objects[source['@id']]
        target_stix = self.stix_objects[target['@id']]
        relationship_type = self.parser.relationship_types.get(rel_type, rel_type)
        if target_stix['type'] == 'course-of-action' and source_stix['type'] == 'course-of-action':
            # Avoid technique-to-technique relationships
            assert rel_type == 'rdfs:subClassOf'
            relationship_type = 'subtechnique-of'
        relationship_id = generate_stix_id("relationship", f"{source_stix['id']}+{target_stix['id']}+{relationship_type}")

        relationship = Relationship(
            id=relationship_id,
            created=self.parser.release_date,
            modified=self.parser.release_date,
            created_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            description=self._get_relationship_description(rel_type, source, target),
            source_ref=source_stix['id'],
            target_ref=target_stix['id'],
            relationship_type=relationship_type,
            object_marking_refs=config.marking_refs,
            external_references=[source_stix['external_references'][0], target_stix['external_references'][0]],
            x_mitre_deprecated=False,
            x_mitre_modified_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            x_mitre_attack_spec_version="3.3.0",
            allow_custom=True,
        )

        return relationship

    def _get_relationship_description(self, rel_type, source_obj, target_obj) -> str:
        """Generate a description for a relationship based on its type"""
        # Get source and target names
        source_name = self._get_name(source_obj)
        target_name = self._get_name(target_obj)

        if rel_type == "rdfs:subClassOf":
            return f"{source_name} is a sub-class of {target_name}"
        if rel_type == "subtechnique-of":
            return f"{source_name} is a sub-technique of {target_name}"
        if rel_type in self.parser.objects_by_id:
            rel_decl = self.parser[rel_type]
            definition = rel_decl.get("d3f:definition", "")

            # Replace 'x' with source name and 'y' with target name
            # Use word boundaries to avoid replacing x/y in the middle of words
            definition = re.sub(r'\bx\b', source_name, definition)
            definition = re.sub(r'\by\b', target_name, definition)

            return definition
        raise ValueError(f"cannot generate description for relationship type: {rel_type}")

    def _convert_artifact_indicators(self) -> List[Any]:
        """Convert D3FEND artifacts to STIX Indicators"""
        indicators = []
        for obj in self.parser.graph:
            if not self.parser.is_indirect_relation_of("rdfs:subClassOf", obj, "d3f:Artifact", "d3f:File", "d3f:NetworkTraffic", "d3f:Software"):
                continue
            artifact_obj = obj
            stix_indicator = self.create_artifact_indicator(artifact_obj)
            self.stix_objects[artifact_obj["@id"]] = stix_indicator
            indicators.append(stix_indicator)
            self.created_artifacts.add(artifact_obj["@id"])
        return indicators

    def create_artifact_indicator(self, artifact_obj: Dict[str, Any]) -> Indicator:
        """Create an Indicator for a D3FEND artifact"""
        artifact_id_raw = artifact_obj["@id"]
        indicator_id = generate_stix_id("indicator", artifact_id_raw)

        # Use the artifact ID as the pattern (hack for d3fend pattern type)
        pattern = artifact_id_raw

        indicator = Indicator(
            id=indicator_id,
            created=self.parser.release_date,
            modified=self.parser.release_date,
            created_by_ref=config.D3FEND2STIX_IDENTITY_OBJECT["id"],
            name=self._get_name(artifact_obj),
            description=self._get_definition(artifact_obj),
            pattern=pattern,
            pattern_type="d3fend",
            indicator_types=["unknown"],
            valid_from=self.parser.release_date,
            external_references=[
                {
                    "source_name": "mitre-d3fend",
                    "url": f"https://d3fend.mitre.org/dao/artifact/{artifact_id_raw}",
                    "external_id": self.get_d3fend_id(artifact_obj),
                },
                *self._extract_references(artifact_obj)
            ],
            object_marking_refs=config.marking_refs,
            allow_custom=True,
        )

        return indicator
    
    @staticmethod
    def get_d3fend_id(obj: Dict[str, Any]) -> str:
        """Extract D3FEND ID from an object"""
        return obj.get("d3f:d3fend-id", obj["@id"])
