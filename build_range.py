#!/usr/bin/env python3

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run build.py for a range of device IDs."
    )
    parser.add_argument("yaml", help="Path to YAML file")
    parser.add_argument(
        "--start-id",
        type=int,
        required=True,
        help="Start device ID (inclusive)",
    )
    parser.add_argument(
        "--end-id",
        type=int,
        required=True,
        help="End device ID (inclusive)",
    )
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="Only compile firmware for each device",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build files before each device build",
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="Recreate virtual environment before first build (passed through)",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue remaining IDs even if one build fails",
    )
    args = parser.parse_args()

    if args.start_id > args.end_id:
        print("Error: --start-id must be less than or equal to --end-id.")
        return 1

    script_dir = Path(__file__).resolve().parent
    build_script = script_dir / "build.py"
    if not build_script.exists():
        print(f"Error: build.py not found at {build_script}")
        return 1

    failures = []

    for device_id in range(args.start_id, args.end_id + 1):
        cmd = [
            sys.executable,
            str(build_script),
            args.yaml,
            "--device-id",
            str(device_id),
        ]
        if args.compile_only:
            cmd.append("--compile-only")
        if args.clean:
            cmd.append("--clean")
        if args.reinstall:
            cmd.append("--reinstall")

        print(f"\n=== Building device_id={device_id} ===")
        print(" ".join(cmd))

        result = subprocess.run(cmd, cwd=script_dir)
        if result.returncode != 0:
            failures.append(device_id)
            print(f"Build failed for device_id={device_id} (exit {result.returncode}).")
            if not args.continue_on_error:
                return result.returncode

    if failures:
        print(f"\nCompleted with failures. Failed IDs: {', '.join(map(str, failures))}")
        return 1

    print(f"\nAll builds completed successfully for IDs {args.start_id}..{args.end_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
