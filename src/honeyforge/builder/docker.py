"""Thin wrappers over the local Docker CLI."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class DockerError(RuntimeError):
    pass


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        raise DockerError("docker CLI not found on PATH")
    return exe


def run(*args: str, capture: bool = False) -> str:
    proc = subprocess.run([_docker(), *args], text=True, capture_output=capture)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip() if capture else ""
        raise DockerError(f"docker {' '.join(args)} failed ({proc.returncode}) {detail}".rstrip())
    return proc.stdout if capture else ""


def pin_digest(image: str) -> str:
    """Pull `image` and return it as repo@sha256:..., so builds are reproducible."""
    if "@sha256:" in image:
        return image
    run("pull", "--quiet", image, capture=True)
    digests = run("image", "inspect", "--format", "{{join .RepoDigests \"\\n\"}}", image, capture=True).split()
    if not digests:
        raise DockerError(f"no registry digest for {image}")
    return digests[0]


def compose(project_dir: str | Path, *args: str, capture: bool = False) -> str:
    project = Path(project_dir)
    return run("compose", "--project-directory", str(project), "-f", str(project / "compose.yaml"), *args,
               capture=capture)
