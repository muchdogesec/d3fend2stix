"""Store STIX objects in bundles"""
import json
import os
import uuid
from stix2 import Bundle
from .config import DEFAULT_CONFIG as config
from .helper import generate_md5_from_list
from .loggings import logger


def store_in_bundle(stix_bundle_path: str, stix_objects: list, filename: str = None) -> str:
    """
    Store STIX objects in a bundle file
    
    Args:
        stix_bundle_path: Path to store the bundle
        stix_objects: List of STIX objects to include
        filename: Optional filename (without extension)
    
    Returns:
        Bundle ID
    """
    data = list(stix_objects)
    
    # Generate deterministic bundle ID
    bundle_id = "bundle--" + str(
        uuid.uuid5(config.namespace, generate_md5_from_list(data))
    )
    
    bundle = Bundle(id=bundle_id, objects=data, allow_custom=True)
    
    # Create folder to store bundle
    os.makedirs(stix_bundle_path, exist_ok=True)
    
    # Determine filename
    if filename:
        if filename.endswith(".json"):
            stix_bundle_file = os.path.join(stix_bundle_path, filename)
        else:
            stix_bundle_file = os.path.join(stix_bundle_path, f"{filename}.json")
    else:
        stix_bundle_file = os.path.join(stix_bundle_path, "d3fend-bundle.json")
    
    logger.info(f"Writing bundle to: {stix_bundle_file}")
    
    with open(stix_bundle_file, "w") as f:
        f.write(json.dumps(json.loads(bundle.serialize()), indent=4))
    
    return bundle.id, stix_bundle_file
