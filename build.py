#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path
import sys


def find_project_root(start: Path) -> Path:
    """
    Walk upwards from start directory until secrets.yaml is found.
    """
    current = start.resolve()
    for parent in [current] + list(current.parents):
        if (parent / "secrets.yaml").exists():
            return parent
    print("Error: Could not find secrets.yaml in any parent directory.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="ESPHome build & upload wrapper"
    )

    parser.add_argument(
        "yaml",
        help="Path to YAML file (relative or absolute)"
    )

    parser.add_argument(
        "--device-id",
        required=True,
        help="Device ID (used for substitutions)"
    )

    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="Only compile, do not upload"
    )

    args = parser.parse_args()

    script_dir = Path(__file__).parent
    project_root = find_project_root(script_dir)

    # Resolve YAML path
    yaml_path = Path(args.yaml).resolve()

    if not yaml_path.exists():
        print(f"YAML file not found: {yaml_path}")
        sys.exit(1)

    # Convert absolute YAML path to project-root-relative path
    try:
        yaml_relative = yaml_path.relative_to(project_root)
    except ValueError:
        print("Error: YAML file must be inside the project directory.")
        sys.exit(1)


    # Ensure secrets.yaml is available in the YAML file's directory
    yaml_dir = yaml_path.parent
    root_secrets = project_root / "secrets.yaml"
    local_secrets = yaml_dir / "secrets.yaml"
    secrets_created = False
    try:
        if not local_secrets.exists():
            try:
                # Try to create a symlink
                local_secrets.symlink_to(root_secrets)
                secrets_created = True
            except Exception:
                # Fallback: copy the file
                import shutil
                shutil.copy2(root_secrets, local_secrets)
                secrets_created = True

        command = [
            "esphome",
            "-s", "device_id", args.device_id,
            "run" if not args.compile_only else "compile",
            str(yaml_relative),
        ]

        print("\nProject root:", project_root)
        print("Running command:")
        print(" ".join(command))
        print()

        subprocess.run(command, check=True, cwd=project_root)
    finally:
        # Clean up the symlink or copied file if we created it
        if secrets_created and local_secrets.exists():
            try:
                local_secrets.unlink()
            except Exception:
                pass


if __name__ == "__main__":
    main()
