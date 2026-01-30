"""Configuration for d3fend2stix"""
from functools import lru_cache
import requests
import json
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
from stix2 import FileSystemStore
from uuid import UUID

load_dotenv()


@lru_cache
def load_file_from_url(url):
    """Load file content from URL with caching"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error loading JSON from {url}: {e}")
        return None


@dataclass
class Config:
    type: str = "d3fend"
    D3FEND2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
    REPO_FOLDER = D3FEND2STIX_FOLDER.parent
    
    # Data paths
    data_path = REPO_FOLDER / "data"
    d3fend_json_file: str = str(data_path / "d3fend-v1_3_0.json")
    
    stix2_objects_folder: str = str(REPO_FOLDER / "stix2_objects")
    stix2_bundles_folder: str = str(REPO_FOLDER / "stix2_bundles")
    
    # UUID namespace for d3fend2stix
    namespace = UUID("6923e7d4-e142-508c-aefc-b5f4dd27dc22")
    
    # Identity and marking definition URLs
    D3FEND2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/dogesec.json"
    D3FEND2STIX_MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/d3fend2stix.json"
    
    # Load identity and marking definition objects
    D3FEND2STIX_IDENTITY_OBJECT = json.loads(load_file_from_url(url=D3FEND2STIX_IDENTITY_URL))
    D3FEND2STIX_MARKING_DEFINITION_OBJECT = json.loads(
        load_file_from_url(url=D3FEND2STIX_MARKING_DEFINITION_URL)
    )
    
    TLP_CLEAR_MARKING_DEFINITION_REF = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    
    # Create necessary directories
    if not os.path.exists(stix2_objects_folder):
        os.makedirs(stix2_objects_folder)
    if not os.path.exists(stix2_bundles_folder):
        os.makedirs(stix2_bundles_folder)
    
    @property
    def fs(self):
        return FileSystemStore(self.stix2_objects_folder)
    
    @property
    def marking_refs(self):
        return [
            self.TLP_CLEAR_MARKING_DEFINITION_REF,
            self.D3FEND2STIX_MARKING_DEFINITION_OBJECT["id"],
        ]
    
    @property
    def default_objects(self):
        return [
            self.D3FEND2STIX_IDENTITY_OBJECT,
            self.D3FEND2STIX_MARKING_DEFINITION_OBJECT,
        ]


DEFAULT_CONFIG = Config()
