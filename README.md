# Anchor - Professional Network Authentication Brute-Forcer

Anchor is a high-performance network authentication brute-forcing tool designed for security professionals and penetration testers. It supports multiple protocols with a focus on HTTP/HTTPS form authentication cracking.

## Repository

GitHub: https://github.com/Art-Hackers/Anchor

## Features

- Multi-protocol support: SSH, SMB, RDP, HTTP, HTTPS, FTP, MySQL, PostgreSQL, MSSQL, Kerberos
- HTTP/HTTPS form authentication cracking with custom field support
- High-performance concurrent scanning
- Proxy support (HTTP/SOCKS)
- Custom headers and User-Agent rotation
- Success/failure pattern matching
- JSON response detection
- Cookie support (Netscape format)
- Rate limiting detection
- Automatic retry on failure
- Configurable delay between requests
- Real-time progress reporting
- Results export to file
- Lightweight with no external dependencies

## Installation

### Prerequisites

- Go 1.21 or higher

### Build from Source

```bash
git clone https://github.com/Art-Hackers/Anchor.git
cd Anchor
go build -ldflags="-s -w" -o anchor.exe main.go
# or do:
dotnet run build.cs
```
### Quick Build (Windows)
```bash
go build -ldflags="-s -w" -o anchor.exe main.go
```

### Usage
**Basic Syntax**

```bash
anchor.exe -target <host:port> -username <user> -wordlist <file> -protocol <protocol> [options]
```
### Command Line Options
Option	                Description	                        Default
-target	Target IP, hostname, or URL (e.g., localhost:8080)	Required
-username	Username to test	Required
-wordlist	Path to password wordlist file	Required
-protocol	Protocol: ssh, smb, rdp, http, https, ftp, mysql, postgres, mssql, kerberos	ssh
-port	Port (auto-detected if not specified)	Protocol default
-timeout	Timeout in milliseconds	5000
-concurrency	Number of concurrent connections	100
-continue	Continue on failure	true
-verbose	Verbose output	false
-output	Output file for found credentials	(none)
-proxy	Proxy server (e.g., http://proxy:8080)	(none)
-delay	Delay between requests in milliseconds	0
-retries	Maximum retries on failure	3
-user-agent	User-Agent string	Mozilla/5.0
-cookies	File containing cookies (Netscape format)	(none)
-form-action	HTTP form action URL	(none)
-success	String indicating successful login	(none)
-fail	String indicating failed login	(none)
-method	HTTP method (GET/POST)	POST
-headers	Additional HTTP headers (key:value,key2:value2)	(none)

### Performance Tuning
Local network: 200-500 concurrent connections

Remote targets: 50-150 concurrent connections

Web applications: 20-50 concurrent connections (avoid rate limiting)

Add delay (-delay 100) to avoid rate limiting

Increase timeout (-timeout 10000) for slow targets

### Security and Legal Notice
This tool is designed for legitimate security testing and auditing purposes only. Use against systems without explicit permission is illegal and unethical.

### Responsible Usage
Only test systems you own or have explicit permission to test

Document all testing activities

Follow responsible disclosure practices

Comply with all applicable laws and regulations

### License
MIT License

### Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

