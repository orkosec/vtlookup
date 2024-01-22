


# vtlookup

`vtlookup` is a web service and command-line tool written in Go for looking up hashes in VirusTotal.

## Getting Started

### Prerequisites

Before using `vtlookup`, make sure you have a VirusTotal API key. You can set it in your environment by adding the following line to your shell profile (e.g., `~/.zshrc` or `~/.bashrc`):

```bash
echo 'export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"' >> ~/.zshrc
```

## Usage

### Web Service

Run the following command to start the web service:

```bash
go run main.go
```

Send your hashes via a POST request using `curl`:

```bash
curl -XPOST 127.0.0.1:8080/vt -d 'hash=70102db9c85f064df588c383cb8d9b662eb8057ea6405b4d81e5c77a27e27ca8,8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b'
```

### Command-Line Tool

You can also use `vtlookup` as a command-line tool by providing a list of hashes in a file:

```bash
go run main.go -file hash.txt
```
