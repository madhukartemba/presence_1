#!/usr/bin/env python3

import argparse
import concurrent.futures
import subprocess
import sys
from pathlib import Path


def find_project_root(start: Path) -> Path | None:
    current = start.resolve()
    for parent in [current] + list(current.parents):
        if (parent / "secrets.yaml").exists():
            return parent
    return None


def ensure_local_secrets(project_root: Path, yaml_path: Path) -> None:
    root_secrets = project_root / "secrets.yaml"
    local_secrets = yaml_path.parent / "secrets.yaml"

    if local_secrets.exists():
        return

    try:
        local_secrets.symlink_to(root_secrets.absolute())
    except Exception:
        # Fall back to copy if symlink is unavailable.
        local_secrets.write_bytes(root_secrets.read_bytes())


def run_build(script_dir: Path, cmd: list[str], device_id: int) -> tuple[int, int, str]:
    result = subprocess.run(
        cmd,
        cwd=script_dir,
        text=True,
        capture_output=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    return device_id, result.returncode, output


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
        "--upload-device",
        default="OTA",
        help="Upload target for ESPHome run (default: OTA). Use 'ask' to show interactive picker.",
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
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Parallel worker count.",
    )
    args = parser.parse_args()

    if args.start_id > args.end_id:
        print("Error: --start-id must be less than or equal to --end-id.")
        return 1
    if args.jobs < 1:
        print("Error: --jobs must be at least 1.")
        return 1

    script_dir = Path(__file__).resolve().parent
    build_script = script_dir / "build.py"
    if not build_script.exists():
        print(f"Error: build.py not found at {build_script}")
        return 1

    yaml_path = Path(args.yaml).resolve()
    if not yaml_path.exists():
        print(f"Error: YAML file not found: {yaml_path}")
        return 1

    project_root = find_project_root(script_dir)
    if not project_root:
        print("Error: Could not find project root containing secrets.yaml.")
        return 1

    # Keep YAML-directory secrets.yaml stable so parallel jobs never race on create/remove.
    ensure_local_secrets(project_root, yaml_path)

    prep_cmd = [
        sys.executable,
        str(build_script),
        args.yaml,
        "--device-id",
        str(args.start_id),
        "--prepare-only",
        "--keep-local-secrets",
    ]
    if args.reinstall:
        prep_cmd.append("--reinstall")

    print("\n=== Preparing shared environment ===")
    print(" ".join(prep_cmd))
    prep_result = subprocess.run(prep_cmd, cwd=script_dir)
    if prep_result.returncode != 0:
        return prep_result.returncode

    failures = []
    device_ids = list(range(args.start_id, args.end_id + 1))

    def build_cmd_for(device_id: int) -> list[str]:
        cmd = [
            sys.executable,
            str(build_script),
            args.yaml,
            "--device-id",
            str(device_id),
            "--upload-device",
            args.upload_device,
            "--keep-local-secrets",
        ]
        if args.compile_only:
            cmd.append("--compile-only")
        if args.clean:
            cmd.append("--clean")
        return cmd

    if args.jobs == 1:
        for device_id in device_ids:
            cmd = build_cmd_for(device_id)
            print(f"\n=== Building device_id={device_id} ===")
            print(" ".join(cmd))

            result = subprocess.run(cmd, cwd=script_dir)
            if result.returncode != 0:
                failures.append(device_id)
                print(f"Build failed for device_id={device_id} (exit {result.returncode}).")
                if not args.continue_on_error:
                    return result.returncode
    else:
        print(f"\n=== Running jobs in parallel (jobs={args.jobs}) ===")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            future_map = {
                executor.submit(run_build, script_dir, build_cmd_for(device_id), device_id): device_id
                for device_id in device_ids
            }
            total = len(future_map)
            completed = 0
            pending = set(future_map.keys())
            print(f"Submitted {total} jobs. Waiting for results...", flush=True)

            while pending:
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=5,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    print(
                        f"[progress] completed {completed}/{total}, running {len(pending)}...",
                        flush=True,
                    )
                    continue

                for future in done:
                    device_id, returncode, output = future.result()
                    completed += 1
                    print(
                        f"\n=== Result for device_id={device_id} (exit {returncode}) "
                        f"[{completed}/{total}] ===",
                        flush=True,
                    )
                    if output.strip():
                        print(output, flush=True)
                    if returncode != 0:
                        failures.append(device_id)

    if failures:
        print(f"\nCompleted with failures. Failed IDs: {', '.join(map(str, failures))}")
        return 1

    print(f"\nAll builds completed successfully for IDs {args.start_id}..{args.end_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
