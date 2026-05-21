import click
from src.core.scanner import Scanner
from src.core.report import Report


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Resistance Infrastructure Gabon — Web Security Scanner"""
    pass


@cli.command()
@click.argument("target")
@click.option("--modules", "-m", multiple=True, default=["all"],
              help="Modules to run: recon, web, vuln, all")
@click.option("--output", "-o", default="reports/report",
              help="Output file path (without extension)")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["html", "json", "pdf"]), default="json")
def scan(target, modules, output, fmt):
    """Run security scan against TARGET (URL or domain)"""
    click.echo(f"[*] Scanning: {target}")
    scanner = Scanner(target, modules=list(modules))
    results = scanner.run()
    report = Report(results)
    report.save(output, fmt=fmt)
    click.echo(f"[+] Report saved: {output}.{fmt}")


if __name__ == "__main__":
    cli()
