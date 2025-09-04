#!/usr/bin/env python3
"""Generate ARC-32 JSON Application Specification for AAS Smart Contract.

This script creates an ARC-32/ARC-4 JSON specification file for the AAS
smart contract, enabling frontend integration and tooling compatibility.
"""

import json
from pathlib import Path
from typing import Optional

from aas.contracts.aas import get_app


def generate_app_spec(output_file: Optional[Path] = None) -> str:
    """Generate ARC-32 application specification JSON.
    
    Args:
        output_file: Optional path to save JSON file
        
    Returns:
        JSON specification as string
    """
    app = get_app()
    
    # Get the application specification dictionary
    spec_dict = app.application_spec()
    
    # Pretty print the JSON
    formatted_json = json.dumps(spec_dict, indent=2, sort_keys=True)
    
    if output_file:
        output_file.write_text(formatted_json)
        print(f"ARC-32 specification saved to: {output_file}")
    
    return formatted_json


def export_app_artifacts(output_dir: Path) -> None:
    """Export all application artifacts to directory.
    
    Args:
        output_dir: Directory to save all artifacts
    """
    app = get_app()
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Dump all artifacts (approval/clear TEAL, ABI contract, app spec)
    app.dump(str(output_dir))
    print(f"Application artifacts exported to: {output_dir}")


def main() -> None:
    """Main entry point for spec generation."""
    # Get project root directory
    project_root = Path(__file__).parent.parent.parent
    
    # Generate ARC-32 spec file
    spec_file = project_root / "aas_arc32_spec.json"
    spec_json = generate_app_spec(spec_file)
    
    # Also export to artifacts directory
    artifacts_dir = project_root / "artifacts"
    export_app_artifacts(artifacts_dir)
    
    print("\n" + "="*60)
    print("AAS Application Specification Generated Successfully")
    print("="*60)
    print(f"Spec file: {spec_file}")
    print(f"Artifacts: {artifacts_dir}")
    print(f"Spec size: {len(spec_json)} characters")


if __name__ == "__main__":
    main()