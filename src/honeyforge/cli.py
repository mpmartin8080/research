from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from honeyforge.spec import check_policy, dump_spec, load_spec
from honeyforge.spec.loader import archetype_names, load_archetype
from honeyforge.spec.policy import has_errors

app = typer.Typer(help="Generate hardened, Claude-driven honeypots that actively signal value.",
                  no_args_is_help=True)


def _load_or_exit(path: Path):
    try:
        return load_spec(path)
    except ValidationError as exc:
        typer.secho(f"{path}: schema validation failed", fg="red", err=True)
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)


@app.command()
def archetypes() -> None:
    """List built-in archetypes."""
    for name in archetype_names():
        spec = load_archetype(name)
        typer.echo(f"{name:12} {spec.persona.role}")


@app.command("init-spec")
def init_spec(
    archetype: str = typer.Option(..., "--archetype", "-a", help="Built-in archetype name"),
    output: Path = typer.Option(..., "--output", "-o", help="Where to write the spec YAML"),
    name: str | None = typer.Option(None, help="Override the honeypot name"),
    force: bool = typer.Option(False, help="Overwrite an existing file"),
) -> None:
    """Write a new spec from an archetype, with freshly minted signal tags."""
    if output.exists() and not force:
        typer.secho(f"{output} exists; pass --force to overwrite", fg="red", err=True)
        raise typer.Exit(1)
    try:
        spec = load_archetype(archetype)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    if name:
        spec.name = name
    dump_spec(spec, output)
    typer.echo(f"wrote {output} ({len(spec.signals)} signals)")


@app.command()
def validate(spec_path: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Schema- and policy-check a spec. Exits non-zero on any error."""
    spec = _load_or_exit(spec_path)
    findings = check_policy(spec)
    for f in findings:
        typer.secho(str(f), fg="red" if f.severity == "error" else "yellow")
    if has_errors(findings):
        raise typer.Exit(1)
    enabled = sum(s.enabled for s in spec.signals)
    typer.secho(f"{spec.name}: OK ({len(spec.services)} services, {enabled}/{len(spec.signals)} signals enabled, "
                f"arm={spec.experiment_arm})", fg="green")


@app.command()
def twin(
    spec_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(..., "--output", "-o"),
    force: bool = typer.Option(False, help="Overwrite an existing file"),
) -> None:
    """Write the passive control twin of an active spec (all signals off)."""
    if output.exists() and not force:
        typer.secho(f"{output} exists; pass --force to overwrite", fg="red", err=True)
        raise typer.Exit(1)
    spec = _load_or_exit(spec_path)
    if spec.experiment_arm != "active":
        typer.secho("spec is already a passive arm", fg="red", err=True)
        raise typer.Exit(1)
    dump_spec(spec.passive_twin(), output)
    typer.echo(f"wrote {output}")


if __name__ == "__main__":
    app()
