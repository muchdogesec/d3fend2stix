"""Miscellaneous helper functions"""
import json
import os
import shutil
import hashlib
import uuid
from .config import DEFAULT_CONFIG as config
from .loggings import logger
from stix2.serialization import serialize as stix_serialize

def generate_stix_id(object_type: str, unique_value: str) -> str:
    """Generate a STIX ID for a given object type and unique value"""
    uuid5 = str(uuid.uuid5(config.namespace, unique_value))
    return f"{object_type}--{uuid5}"


def generate_md5_from_list(stix_objects: list) -> str:
    """Generate MD5 hash from sorted list of STIX objects"""
    stix_objects = sorted(stix_objects, key=lambda obj: obj.get("id"))
    json_str = stix_serialize(stix_objects).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()


def clean_filesystem(path=None):
    """Clean the file system before generating new objects"""
    logger.info("Deleting old data from filesystem")
    target_path = path if path else config.stix2_objects_folder
    
    if os.path.exists(target_path):
        for filename in os.listdir(target_path):
            file_path = os.path.join(target_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logger.error(f"Failed to delete {file_path}. Reason: {e}")
    
    logger.info("Deletion done!")


def extract_id_from_uri(uri: str) -> str:
    """Extract ID from d3f URI (e.g., 'd3f:Detect' -> 'Detect')"""
    if ":" in uri:
        return uri.split(":")[-1]
    return uri


def safe_get(obj, key, default=None):
    """Safely get a value from object, handling both dict and @id references"""
    value = obj.get(key, default)
    if isinstance(value, dict) and "@id" in value:
        return value["@id"]
    return value

def ensure_list(value):
    """Ensure the value is returned as a list"""
    if isinstance(value, list):
        return value
    elif value is None:
        return []
    else:
        return [value]
    
def stix_as_dict(stix_object):
    """Convert a STIX object to a dictionary"""
    return json.loads(stix_serialize(stix_object))