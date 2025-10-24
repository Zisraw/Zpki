# Zpki

A simple and efficient command-line tool for generating certificates with CA management.

Zpki will generate a keypair and a root certificate in the current directory + a keypair and a leaf certificate based on the SAN or IP arguments in a sub-directory.

Certificate vailidy is 2 years (730 days)

## Installation

### From Source

```bash
git clone https://github.com/Zisraw/Zpki.git
cd zpki
cargo build --release
```

The binary will be available at `target/release/zpki`

## Usage

### Basic Usage with SAN

Generate a certificate with a domain name:

```bash
zpki --san example.com
```

### Multiple SANs

```bash
zpki --san example.com api.example.com
```

### IP Addresses

Generate a certificate for an IP address:

```bash
zpki --ip 192.168.1.100
```

### Combined SANs and IPs

```bash
zpki --san localhost --ip 127.0.0.1 192.168.1.100
```

## Output Structure

After running zpki, you'll get the following structure:

```
./
├── zpki-root-key.pem       # Root CA private key (generated once)
├── zpki-root-cert.pem      # Root CA certificate (generated once)
└── <subject-name>/         # Directory named after first SAN/IP
    ├── key.pem             # Leaf certificate private key
    └── cert.pem            # Leaf certificate
```

## Examples

### Web Server (nginx)

```bash
zpki --san myapp.local
```

Then in your nginx config:
```nginx
ssl_certificate     /path/to/myapp.local/cert.pem;
ssl_certificate_key /path/to/myapp.local/key.pem;
```

### Docker Compose

```bash
zpki --san db.local --san api.local
```

### Local Development with Hosts File

```bash
zpki --san dev.example.com
# Add to /etc/hosts: 127.0.0.1 dev.example.com
```


