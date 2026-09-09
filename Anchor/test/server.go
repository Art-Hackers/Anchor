package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Valid credentials for testing
var validCredentials = map[string]string{
	"admin":   "password123",
	"user":    "letmein",
	"test":    "qwerty",
	"root":    "root123",
	"demo":    "demo123",
	"guest":   "guest123",
	"support": "support123",
}

func main() {
	// Serve static files
	http.HandleFunc("/", handleLogin)
	http.HandleFunc("/login", handleLoginPost)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)

	fmt.Println("============================================================")
	fmt.Println("  Anchor Test Server - Login Form Testing")
	fmt.Println("============================================================")
	fmt.Println("Server running at: http://localhost:8080")
	fmt.Println("\nTest Credentials:")
	fmt.Println("  admin:password123")
	fmt.Println("  user:letmein")
	fmt.Println("  test:qwerty")
	fmt.Println("  root:root123")
	fmt.Println("  demo:demo123")
	fmt.Println("\nTo test Anchor:")
	fmt.Println("  anchor.exe -target http://localhost:8080 -username admin -wordlist passwords.txt -protocol http")
	fmt.Println("============================================================")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login - Test Site</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            width: 350px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 24px;
        }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo span { font-size: 48px; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #667eea;
            outline: none;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s;
        }
        button:hover { transform: scale(1.02); }
        button:active { transform: scale(0.98); }
        .message {
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            display: none;
        }
        .message.error {
            background: #fee;
            color: #c33;
            display: block;
            border: 1px solid #fcc;
        }
        .message.success {
            background: #efe;
            color: #3c3;
            display: block;
            border: 1px solid #cfc;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #888;
            font-size: 12px;
        }
        .hint {
            color: #999;
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
            padding: 10px;
            background: #f5f5f5;
            border-radius: 5px;
        }
        .error-msg {
            color: #c33;
            font-size: 14px;
            text-align: center;
            margin-top: 10px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo"><span>🔐</span></div>
        <h1>Secure Login</h1>
        
        <form id="loginForm" method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        
        <div id="message" class="message"></div>
        
        <div class="hint">
            <strong>Test Credentials:</strong><br>
            admin:password123<br>
            user:letmein<br>
            test:qwerty
        </div>
        
        <div class="footer">
            Test Site for Anchor v2.0.0
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const messageDiv = document.getElementById('message');
            
            // Submit to server
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    messageDiv.className = 'message success';
                    messageDiv.textContent = '✅ Login successful! Welcome ' + username + '!';
                    messageDiv.style.display = 'block';
                    setTimeout(function() {
                        window.location.href = '/dashboard?username=' + encodeURIComponent(username);
                    }, 2000);
                } else {
                    messageDiv.className = 'message error';
                    messageDiv.textContent = '❌ ' + data.message;
                    messageDiv.style.display = 'block';
                    document.getElementById('password').value = '';
                }
            })
            .catch(error => {
                messageDiv.className = 'message error';
                messageDiv.textContent = '❌ Error connecting to server';
                messageDiv.style.display = 'block';
            });
        });
    </script>
</body>
</html>
`
	fmt.Fprint(w, tmpl)
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	// Check credentials
	if validPassword, exists := validCredentials[username]; exists && validPassword == password {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success": true, "message": "Login successful", "username": "%s"}`, username)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": false, "message": "Invalid username or password"}`)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "User"
	}

	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Test Site</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
        }
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 15px 30px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar h1 { font-size: 20px; }
        .navbar a {
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            background: rgba(255,255,255,0.2);
            border-radius: 5px;
            transition: background 0.3s;
        }
        .navbar a:hover { background: rgba(255,255,255,0.3); }
        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        .welcome-card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .welcome-card h2 { color: #333; margin-bottom: 10px; }
        .welcome-card p { color: #666; line-height: 1.6; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-card .label { color: #888; margin-top: 5px; }
        .content-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h3 { color: #333; margin-bottom: 15px; }
        .card ul { list-style: none; }
        .card ul li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
            color: #555;
        }
        .card ul li:last-child { border-bottom: none; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge.success { background: #d4edda; color: #155724; }
        .badge.warning { background: #fff3cd; color: #856404; }
        .badge.danger { background: #f8d7da; color: #721c24; }
        @media (max-width: 768px) {
            .content-grid { grid-template-columns: 1fr; }
            .navbar { flex-direction: column; gap: 10px; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🏠 Dashboard</h1>
        <div>
            <span style="margin-right: 15px;">Welcome, <strong>` + username + `</strong></span>
            <a href="/logout">Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="welcome-card">
            <h2>Welcome to the Secure Dashboard!</h2>
            <p>You have successfully logged in. This is a test site for Anchor - the professional network authentication brute-forcer.</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">1,234</div>
                <div class="label">Total Users</div>
            </div>
            <div class="stat-card">
                <div class="number">567</div>
                <div class="label">Active Sessions</div>
            </div>
            <div class="stat-card">
                <div class="number">89%</div>
                <div class="label">System Uptime</div>
            </div>
            <div class="stat-card">
                <div class="number">42</div>
                <div class="label">Security Alerts</div>
            </div>
        </div>

        <div class="content-grid">
            <div class="card">
                <h3>📋 Recent Activity</h3>
                <ul>
                    <li>User login from IP 192.168.1.100 <span class="badge success">Success</span></li>
                    <li>Failed login attempt from IP 10.0.0.5 <span class="badge danger">Failed</span></li>
                    <li>Password change for user: admin <span class="badge warning">Pending</span></li>
                    <li>New user registration: john_doe <span class="badge success">Success</span></li>
                    <li>API key generated for service: Monitor <span class="badge success">Success</span></li>
                </ul>
            </div>
            <div class="card">
                <h3>🔐 Security Status</h3>
                <ul>
                    <li>SSL Certificate: <span class="badge success">Valid</span></li>
                    <li>Firewall: <span class="badge success">Active</span></li>
                    <li>2FA: <span class="badge warning">Not Enabled</span></li>
                    <li>Last Scan: 2 hours ago</li>
                    <li>Intrusions: <span class="badge success">0</span></li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
`
	fmt.Fprint(w, tmpl)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
