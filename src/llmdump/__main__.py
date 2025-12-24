"""Allow running llmdump as a module: python -m llmdump"""

from .cli.main import cli

if __name__ == '__main__':
    cli()
