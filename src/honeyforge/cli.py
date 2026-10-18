from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from honeyforge.builder import docker
from honeyforge.events import parse_line
from honeyforge.render import DEFAULT_BASE_IMAGE, DEFAULT_NETGUARD_IMAGE, render_project
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


def _render_or_exit(spec, outdir: Path, base_image: str, netguard_base: str = DEFAULT_NETGUARD_IMAGE) -> Path:
    try:
        return render_project(spec, outdir, base_image=base_image, netguard_base=netguard_base)
    except (ValueError, NotImplementedError) as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)


def _default_outdir(spec_path: Path) -> Path:
    return Path("out") / spec_path.stem


@app.command()
def render(
    spec_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path | None = typer.Option(None, "--output", "-o", help="Build context dir (default out/<spec>)"),
    base_image: str = typer.Option(DEFAULT_BASE_IMAGE, help="Base image (tag or repo@sha256 digest)"),
) -> None:
    """Render a spec into a Docker build context and compose project, without building."""
    spec = _load_or_exit(spec_path)
    compose_file = _render_or_exit(spec, output or _default_outdir(spec_path), base_image)
    typer.echo(f"rendered {compose_file.parent}")


@app.command()
def build(
    spec_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path | None = typer.Option(None, "--output", "-o", help="Build context dir (default out/<spec>)"),
    base_image: str = typer.Option(DEFAULT_BASE_IMAGE, help="Base image; pinned to its digest before building"),
) -> None:
    """Render a spec, pin the base image digest, and build the honeypot image."""
    spec = _load_or_exit(spec_path)
    try:
        pinned = docker.pin_digest(base_image)
        netguard_pinned = docker.pin_digest(DEFAULT_NETGUARD_IMAGE)
        typer.echo(f"base images pinned: {pinned}, {netguard_pinned}")
        compose_file = _render_or_exit(spec, output or _default_outdir(spec_path), pinned, netguard_pinned)
        docker.compose(compose_file.parent, "build")
    except docker.DockerError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    typer.secho(f"built honeyforge/{spec.name}:latest ({compose_file.parent})", fg="green")


def _compose_cmd(project: Path, *args: str) -> None:
    if not (project / "compose.yaml").is_file():
        typer.secho(f"{project} has no compose.yaml; run `honeyforge build` first", fg="red", err=True)
        raise typer.Exit(1)
    try:
        docker.compose(project, *args)
    except docker.DockerError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)


@app.command()
def up(project: Path = typer.Argument(..., file_okay=False)) -> None:
    """Start a built honeypot (detached)."""
    _compose_cmd(project, "up", "--detach", "--wait")


@app.command()
def down(project: Path = typer.Argument(..., file_okay=False),
         volumes: bool = typer.Option(False, "--volumes", help="Also delete the event volume")) -> None:
    """Stop and remove a running honeypot."""
    _compose_cmd(project, "down", *(["--volumes"] if volumes else []))


@app.command()
def events(project: Path = typer.Argument(..., file_okay=False),
           include_boot: bool = typer.Option(False, help="Include OpenCanary startup/system events")) -> None:
    """Print a running honeypot's events as normalised JSON lines."""
    lock = project / "spec.lock.yaml"
    if not lock.is_file():
        typer.secho(f"{lock} not found", fg="red", err=True)
        raise typer.Exit(1)
    spec = load_spec(lock)
    try:
        raw = docker.compose(project, "logs", "--no-color", "--no-log-prefix", "decoy", capture=True)
    except docker.DockerError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    for line in raw.splitlines():
        event = parse_line(line, spec)
        if event and (include_boot or event.is_interaction):
            typer.echo(event.model_dump_json())


if __name__ == "__main__":
    app()
