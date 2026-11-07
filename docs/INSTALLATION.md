# Installation Guide

This guide explains how to install, verify, update, and uninstall RRI
(Recon Intelligence) CLI.

## 1. System Requirements

RRI requires:

- Python 3.11 or newer.
- pip.
- pipx (recommended installation method).
- Internet access during the initial installation to retrieve required
  packages, if they are not already available locally.

### Tested Environment

RRI has been developed and tested in:

- Kali Linux Rolling.
- Python 3.13.
- Linux ARM64 environment.

Other Python-compatible environments may work, but have not necessarily
been tested.

## 2. Obtain the Source Code

Clone the official repository:

    git clone https://github.com/rcsyem/rri.git
    cd rri

If you already have a local copy of the source code, navigate to its root
directory instead.

## 3. Recommended Installation: pipx

pipx installs RRI in an isolated Python environment and exposes the `rri`
command on your PATH. You do not need to activate a virtual environment
before running the command.

### Install pipx

On Kali Linux and Debian-based systems:

    sudo apt update
    sudo apt install pipx

Then configure the executable path:

    pipx ensurepath

Restart your terminal if necessary.

On other Linux distributions, install pipx using the distribution's
recommended package manager or installation instructions.

### Install RRI

From the RRI project root directory:

    pipx install .

pipx creates an isolated environment, installs the project and its declared
dependencies, and registers the `rri` command.

The current runtime dependency is:

- aiohttp (version 3.12 or newer, but below version 4).

### Verify the Installation

    rri --version
    rri --help

You can also check where the command is installed:

    command -v rri

The command should be available from directories outside the project.

## 4. Alternative Installation: Virtual Environment

A virtual environment is also supported and can be useful for development.

Create the environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install RRI:

    python -m pip install -e .

Verify:

    rri --version
    rri --help

You can run the executable directly without activating the environment:

    .venv/bin/rri --version

## 5. Run the Automated Tests

When using the source repository and its virtual environment, run:

    .venv/bin/python -m unittest discover -s tests -v

These tests are designed to validate the implementation without requiring
an actual scan of an external website.

## 6. Running RRI

RRI requires the target URL to be supplied explicitly at runtime.

Example:

    rri -u https://example.com

Only scan systems that you own or have explicit authorization to assess.

See the [CLI Reference](CLI.md) for available command-line options.

## 7. Updating RRI

If RRI was installed through pipx from a cloned Git repository, navigate to
the repository and retrieve the latest source changes:

    cd rri
    git pull

Then reinstall the updated local project:

    pipx install --force .

Review the project's changelog before using a new version.

For a virtual-environment installation, activate the environment and run:

    git pull
    python -m pip install -e .

## 8. Uninstalling RRI

### pipx installation

    pipx uninstall rri-recon-intelligence

This removes the pipx environment and its registered command. It does not
delete the cloned source repository or generated reports.

### Virtual-environment installation

Activate the environment, then run:

    python -m pip uninstall rri-recon-intelligence
    deactivate
    rm -rf .venv

Removing the virtual environment does not delete the project source files
or generated reports.

## 9. Troubleshooting

### `python3: command not found`

Python 3 is not available through the current shell PATH. Install Python
3.11 or newer using your operating system's package manager.

### `No module named venv`

The Python virtual environment component may not be installed. Install the
matching venv package for your Python version.

### `pipx: command not found`

Install pipx using your operating system's package manager, then reopen
your terminal.

### `rri: command not found` after pipx installation

Run:

    pipx ensurepath

Then restart your terminal and check:

    pipx list
    command -v rri

Make sure the pipx application directory is included in your PATH.

For a virtual-environment installation, activate the environment:

    source .venv/bin/activate

Alternatively, run the executable directly:

    .venv/bin/rri --help

### Dependency installation fails

Check that:

- Your Python version satisfies the project requirement.
- pip and the required build tools are available.
- The installation environment can access the package sources.
- The dependency versions are compatible with the project configuration.

### Permission errors

For regular users, prefer pipx or a virtual environment instead of installing
project dependencies directly into the system Python environment.

## 10. Additional Documentation

- [Command-Line Reference](CLI.md)
- [Architecture](ARCHITECTURE.md)
- [Recon Modules](RECON-MODULES.md)
- [Scope and Safety](SCOPE-AND-SAFETY.md)
- [Reporting](REPORTING.md)
- [Testing](TESTING.md)
- [Development Guide](DEVELOPMENT.md)

---

RRI is an authorization-based reconnaissance tool. Installation does not
grant permission to scan any system.
