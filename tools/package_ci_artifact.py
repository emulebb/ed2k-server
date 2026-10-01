#!/usr/bin/env python3
"""Assemble a deterministic Linux x86-64 CI artifact for ed2k-server."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import shutil
import tarfile
import tempfile
import tomllib
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for CI artifact assembly."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def copy_tree(source: Path, destination: Path) -> None:
    """Copy a tracked runtime-support tree into artifact staging."""

    shutil.copytree(source, destination)


def normalized_tar_info(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Normalize archive ownership and timestamps for reproducible output."""

    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info


def sha256(path: Path) -> str:
    """Return the lowercase SHA-256 digest for one file."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    """Build the candidate bundle and matching SHA-256 file."""

    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    binary = args.binary.resolve()
    output_dir = args.output_dir.resolve()
    if not binary.is_file():
        raise RuntimeError(f"Release binary is missing: {binary}")

    cargo_manifest = tomllib.loads((repo_root / "Cargo.toml").read_text(encoding="utf-8"))
    version = str(cargo_manifest["package"]["version"])
    bundle_name = f"ed2k-server-{version}-linux-x86_64"
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{bundle_name}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="ed2k-server-artifact-") as temporary:
        package_root = Path(temporary) / bundle_name
        package_root.mkdir()
        staged_binary = package_root / "ed2k-server"
        shutil.copy2(binary, staged_binary)
        staged_binary.chmod(0o755)
        for filename in ("README.md", "UPDATE-SERVICE.md", "LICENSE"):
            shutil.copy2(repo_root / filename, package_root / filename)
        copy_tree(repo_root / "config", package_root / "config")
        copy_tree(repo_root / "contrib", package_root / "contrib")
        with archive_path.open("wb") as raw_archive:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_archive, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    archive.add(package_root, arcname=bundle_name, filter=normalized_tar_info)

    checksum_path = output_dir / f"{archive_path.name}.sha256"
    checksum_path.write_text(f"{sha256(archive_path)}  {archive_path.name}\n", encoding="utf-8", newline="\n")
    print(archive_path)
    print(checksum_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
