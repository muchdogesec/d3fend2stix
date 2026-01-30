"""Create STIX objects from D3FEND data"""
import uuid
from typing import Dict, List, Any, Optional
from stix2 import CourseOfAction, Indicator, Relationship, CustomObject
from stix2.properties import StringProperty, ListProperty, TypeProperty, IDProperty, ReferenceProperty
from stix2.base import _STIXBase
from .config import DEFAULT_CONFIG as config
from .helper import extract_id_from_uri
from .loggings import logger




@CustomObject(type='x-mitre-tactic', properties=[
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('x_mitre_shortname', StringProperty(required=True)),
])
class D3FENDTactic(_STIXBase):
    pass

# Custom STIX objects for D3FEND
@CustomObject('x-mitre-matrix', [
    ('id', IDProperty('x-mitre-matrix', spec_version='2.1')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('tactic_refs', ListProperty(ReferenceProperty(valid_types=['x-mitre-tactic']))),
])
class Matrix(_STIXBase):
    pass
