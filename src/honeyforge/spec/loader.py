from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from honeyforge.spec.models import HoneypotSpec


def load_spec(path: str | Path) -> HoneypotSpec:
    with open(path, encoding="utf-8") as fh:
        return HoneypotSpec.model_validate(yaml.safe_load(fh))


def dump_spec(spec: HoneypotSpec, path: str | Path) -> None:
    data = spec.model_dump(mode="json", exclude_defaults=False)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def archetype_names() -> list[str]:
    root = resources.files("honeyforge") / "archetypes"
    return sorted(p.name.removesuffix(".yaml") for p in root.iterdir() if p.name.endswith(".yaml"))


def load_archetype(name: str) -> HoneypotSpec:
    """Load a built-in archetype. Signal tags are freshly minted on each load, so every
    honeypot created from an archetype gets unique, attributable tags."""
    path = resources.files("honeyforge") / "archetypes" / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"unknown archetype {name!r}; choose from {archetype_names()}")
    return HoneypotSpec.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
