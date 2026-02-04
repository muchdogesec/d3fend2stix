"""Main entry point for d3fend2stix"""
import json
from pathlib import Path
import sys

from d3fend2stix.stix_store import store_in_bundle
from .parser import D3FENDParser
from .converter import D3FENDConverter
# from .stix_store import store_in_bundle
from .config import DEFAULT_CONFIG as config
from .helper import clean_filesystem
from .loggings import logger


def main():
        logger.info("="*60)
        logger.info("D3FEND to STIX Conversion Starting")
        logger.info("="*60)
        
        # Clean filesystem
        clean_filesystem(config.stix2_objects_folder)
        
        # Step 1: Load and parse D3FEND data
        logger.info("Step 1: Loading D3FEND data")
        parser = D3FENDParser(config.d3fend_json_file)
        parser.load_data()
        
        # Step 2: Convert to STIX objects
        logger.info("Step 2: Converting to STIX objects")
        converter = D3FENDConverter(parser)
        stix_objects = converter.convert()
        
        # Step 4: Create bundle
        logger.info("Step 4: Creating STIX bundle")
        version_str = parser.version.replace(".", "_")
        bundle_id, bundle_path = store_in_bundle(
            config.stix2_bundles_folder,
            stix_objects,
            filename=f"d3fend-v{version_str}-bundle"
        )
        rel_path = Path(config.stix2_bundles_folder) / f"d3fend-v{version_str}-external-relationships.json"
        rel_path.write_text(json.dumps(converter.other_relationships, indent=4))
        
        logger.info("="*60)
        logger.info(f"Conversion Complete!")
        logger.info(f"Bundle ID: {bundle_id}")
        logger.info(f"Total objects: {len(stix_objects)}")
        logger.info(f"Bundle location: {bundle_path}")
        logger.info(f"Total unprocessed refs: {len(converter.other_relationships)}")
        logger.info(f"External refs location: {rel_path}")
        logger.info("="*60)


if __name__ == "__main__":
    sys.exit(main())
