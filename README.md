# Goran - Domain & IP Analysis CLI

**Goran** is a Rust-based command-line tool designed to gather detailed information about domain names and IP addresses. It integrates several data sources such as WHOIS, Geolocation, DNS, SSL certificates, and VirusTotal reputation checks. Goran uniquely utilizes a Gemini to generate concise, readable reports and analyses.

## Features
- **Geolocation**: Retrieve geographic and ISP data.
- **WHOIS & RDAP**: Detailed domain registration data.
- **DNS Lookup**: Information about DNS records (A, AAAA, MX, NS).
- **SSL Check**: Certificate issuer, validity dates, and DNS names.
- **VirusTotal**: Security analysis and reputation scoring.
- **LLM Analysis**: AI-generated concise report summarizing findings and providing a verdict.

## Why Use Goran?
Unlike traditional WHOIS queries, Goran:
- Integrates multiple data sources into a single, comprehensive report.
- Enhances readability with colored output and clear summaries.
- Utilizes AI (Gemini) to interpret and succinctly analyze results, providing meaningful insights.

## Installation

### Using Homebrew (Recommended for macOS)
```sh
brew tap beowolx/goran
brew install goran
```

### Using Cargo
Make sure you have Rust installed, then run:
```sh
cargo install goran
```

## Usage
```sh
goran example.com
```

### CLI Flags Explained
| Flag                     | Description                                                |
|--------------------------|------------------------------------------------------------|
| `--vt`                   | Enable VirusTotal reputation checks (requires API key).    |
| `--vt-api-key`           | Provide VirusTotal API key directly via CLI.               |
| `--json`                 | Output results in JSON format.                             |
| `--no-whois`             | Skip WHOIS lookup step.                                    |
| `--no-dns`               | Skip DNS lookup step.                                      |
| `--no-ssl`               | Skip SSL certificate checks.                               |
| `--llm-report`           | Generate an AI-based narrative report (requires Gemini API).|
| `--llm-api-key`          | Provide Gemini API key directly via CLI.                   |
| `--save-keys`            | Persist provided API keys in local config.                 |
| `--config-show`          | Display current merged configuration settings.             |

### Obtaining API Keys

- **Gemini API Key**:
  - Sign up at [Google AI Studio](https://ai.google.dev/gemini-api/docs/api-key).
  - Generate your API key from the dashboard.

- **VirusTotal API Key**:
  - Register at [VirusTotal](https://www.virustotal.com/gui/join-us).
  - Obtain your free API key from the settings panel.

### Using VirusTotal
Goran uses VirusTotal to check the reputation of the domain and IP address. VirusTotal is a cloud-based antivirus engine for detecting malicious software but it can also be used to check the reputation of a domain or IP address.

To use VirusTotal, run:
```sh
goran example.com --vt --vt-api-key <VT_API_KEY>
```

### Generating Gemini Analysis
Goran uses `gemini-2.0-flash` to generate an AI-powered report. The goal is to provide a concise and readable report that is easy to understand.

To generate an AI-powered report, run:

```sh
goran example.com --llm-report --llm-api-key <GEMINI_API_KEY>
```

### Saving API Keys
To avoid having to provide your API keys every time you run Goran, you can save them in the config file.

```sh
goran example.com --vt --vt-api-key <VT_API_KEY> --llm-report --llm-api-key <GEMINI_API_KEY> --save-keys
```

Subsequent executions will use these saved keys automatically.

To list the current saved keys, run:

```sh
goran --config-show
```

## Configuration File
Configuration settings and saved keys are stored here:
- **Linux**: `~/.config/rs.goran/default-config.toml`
- **macOS**: `~/Library/Application Support/rs.goran/default-config.toml`
- **Windows**: `%APPDATA%\rs.goran\default-config.toml`

## Contributions
Feel free to open issues and submit pull requests on [GitHub](https://github.com/beowolx/goran).

## License
Distributed under the MIT License. See `LICENSE` for details.
