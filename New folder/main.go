package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure Go driver (No CGO required)
)

const SecretKey = "YourSuperSecretAdminKeyChangeMe"

var db *sql.DB

type KeyRecord struct {
	ID        int       `json:"id"`
	KeyCode   string    `json:"key_code"`
	Duration  string    `json:"duration"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsRevoked bool      `json:"is_revoked"`
}

type KeyRequest struct {
	Duration string `json:"duration"`
}

type RevokeRequest struct {
	Key string `json:"key"`
}

func main() {
	var err error
	// Note: driver name is "sqlite", NOT "sqlite3"
	db, err = sql.Open("sqlite", "./keys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/generate", handleGenerate)
	http.HandleFunc("/api/validate", handleValidate)
	http.HandleFunc("/api/keys", handleListKeys)
	http.HandleFunc("/api/revoke", handleRevoke)

	fmt.Println("🚀 Admin Panel running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func createTable() {
	query := `
	CREATE TABLE IF NOT EXISTS keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_code TEXT UNIQUE NOT NULL,
		duration TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		is_revoked BOOLEAN DEFAULT 0
	);`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("dashboard").Parse(indexHTML))
	tmpl.Execute(w, nil)
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req KeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Invalid input"})
		return
	}

	var expiresAt time.Time
	now := time.Now()

	switch strings.ToUpper(req.Duration) {
	case "DAY":
		expiresAt = now.Add(24 * time.Hour)
	case "WEEK":
		expiresAt = now.Add(7 * 24 * time.Hour)
	case "MONTH":
		expiresAt = now.Add(30 * 24 * time.Hour)
	default:
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Invalid duration"})
		return
	}

	keyCode := GenerateKey(req.Duration, expiresAt)

	_, err := db.Exec("INSERT INTO keys (key_code, duration, created_at, expires_at) VALUES (?, ?, ?, ?)",
		keyCode, strings.ToUpper(req.Duration), now, expiresAt)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to save key to database"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"key":        keyCode,
		"duration":   strings.ToUpper(req.Duration),
		"expires_at": expiresAt.Format(time.RFC1123),
	})
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Invalid input"})
		return
	}

	valid, duration, expiresAt, err := ValidateKey(req.Key)
	if !valid {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}

	var isRevoked bool
	err = db.QueryRow("SELECT is_revoked FROM keys WHERE key_code = ?", req.Key).Scan(&isRevoked)
	if err == sql.ErrNoRows {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Key not registered on server"})
		return
	} else if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Database error"})
		return
	}

	if isRevoked {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Key has been revoked by admin"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"duration":   duration,
		"expires_at": expiresAt.Format(time.RFC1123),
	})
}

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("SELECT id, key_code, duration, created_at, expires_at, is_revoked FROM keys ORDER BY id DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []KeyRecord
	for rows.Next() {
		var k KeyRecord
		rows.Scan(&k.ID, &k.KeyCode, &k.Duration, &k.CreatedAt, &k.ExpiresAt, &k.IsRevoked)
		keys = append(keys, k)
	}

	json.NewEncoder(w).Encode(keys)
}

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false})
		return
	}

	_, err := db.Exec("UPDATE keys SET is_revoked = 1 WHERE key_code = ?", req.Key)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Database update failed"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func GenerateKey(duration string, expiresAt time.Time) string {
	timestampStr := strconv.FormatInt(expiresAt.Unix(), 10)
	payload := strings.ToUpper(duration) + "-" + timestampStr
	signature := createHMAC(payload, SecretKey)
	return fmt.Sprintf("%s-%s", payload, signature)
}

func ValidateKey(key string) (bool, string, time.Time, error) {
	parts := strings.Split(key, "-")
	if len(parts) != 3 {
		return false, "", time.Time{}, fmt.Errorf("malformed key structure")
	}

	durationStr := parts[0]
	timestampStr := parts[1]
	providedSig := parts[2]

	payload := durationStr + "-" + timestampStr
	expectedSig := createHMAC(payload, SecretKey)

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return false, "", time.Time{}, fmt.Errorf("invalid signature")
	}

	unixTimestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("invalid expiration timestamp")
	}
	expiresAt := time.Unix(unixTimestamp, 0)

	if time.Now().After(expiresAt) {
		return false, durationStr, expiresAt, fmt.Errorf("key has expired")
	}

	return true, durationStr, expiresAt, nil
}

func createHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

const indexHTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - KeyGen & Server DB</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {
        darkMode: 'class',
        theme: {
          extend: { colors: { brand: { 500: '#6366f1', 600: '#4f46e5' } } }
        }
      }
    </script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans">
    <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-8 w-8 rounded-lg bg-brand-600 flex items-center justify-center font-bold text-lg shadow-lg">🔑</div>
                <span class="font-semibold text-lg tracking-tight">KeyGen Server Dashboard</span>
            </div>
            <span class="text-xs font-mono bg-slate-800 text-slate-400 px-3 py-1 rounded-full border border-slate-700">SQLite Server Engine</span>
        </div>
    </nav>

    <main class="flex-1 max-w-6xl w-full mx-auto px-6 py-10 space-y-8">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <section class="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
                <h2 class="text-xl font-bold mb-1 flex items-center gap-2"><span>⚡</span> Generate Key</h2>
                <p class="text-slate-400 text-sm mb-6">Create keys and persist them into SQLite database.</p>
                <div class="grid grid-cols-3 gap-3 mb-6">
                    <button onclick="setDuration('DAY')" id="btn-DAY" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Day</button>
                    <button onclick="setDuration('WEEK')" id="btn-WEEK" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Week</button>
                    <button onclick="setDuration('MONTH')" id="btn-MONTH" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Month</button>
                </div>
                <button onclick="generateKey()" class="w-full bg-brand-600 hover:bg-brand-500 text-white font-medium py-3 rounded-xl transition shadow-lg">Generate & Save</button>
            </section>

            <section class="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
                <h2 class="text-xl font-bold mb-1 flex items-center gap-2"><span>🛡️</span> Validate Key</h2>
                <p class="text-slate-400 text-sm mb-6">Checks cryptographic hash & server revocation status.</p>
                <input type="text" id="val-input" placeholder="Paste Key Here..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm font-mono mb-4 text-slate-100">
                <button onclick="validateKey()" class="w-full bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium py-3 rounded-xl transition">Validate Key</button>
                <div id="val-result" class="hidden mt-4 p-3 rounded-xl border border-slate-800 bg-slate-950/60 text-xs"></div>
            </section>
        </div>

        <section class="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl font-bold flex items-center gap-2"><span>🗄️</span> Saved Keys Database</h2>
                <button onclick="loadKeys()" class="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 px-3 py-1.5 rounded-lg">Refresh DB</button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm text-slate-400">
                    <thead class="bg-slate-950 text-slate-300 uppercase text-xs">
                        <tr>
                            <th class="p-3">ID</th>
                            <th class="p-3">Key</th>
                            <th class="p-3">Duration</th>
                            <th class="p-3">Expires At</th>
                            <th class="p-3">Status</th>
                            <th class="p-3 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody id="keys-table-body" class="divide-y divide-slate-800"></tbody>
                </table>
            </div>
        </section>
    </main>

    <script>
        let selectedDuration = 'DAY';
        setDuration('DAY');

        function setDuration(dur) {
            selectedDuration = dur;
            document.querySelectorAll('.dur-btn').forEach(btn => btn.className = 'dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm');
            document.getElementById('btn-' + dur).className = 'dur-btn border-brand-500 bg-brand-600/10 text-brand-400 py-3 rounded-xl font-medium text-sm';
        }

        async function generateKey() {
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ duration: selectedDuration })
            });
            await loadKeys();
        }

        async function validateKey() {
            const inputKey = document.getElementById('val-input').value.trim();
            if(!inputKey) return;
            const res = await fetch('/api/validate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ key: inputKey })
            });
            const data = await res.json();
            const resultBox = document.getElementById('val-result');
            resultBox.classList.remove('hidden');
            if(data.success) {
                resultBox.innerHTML = '<span class="text-emerald-400 font-bold">✓ VALID</span> - Expiration: ' + data.expires_at;
            } else {
                resultBox.innerHTML = '<span class="text-rose-400 font-bold">✗ INVALID</span> - Reason: ' + data.error;
            }
        }

        async function loadKeys() {
            const res = await fetch('/api/keys');
            const keys = await res.json();
            const tbody = document.getElementById('keys-table-body');
            tbody.innerHTML = '';
            
            if(!keys || keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-slate-600">No keys saved in database.</td></tr>';
                return;
            }

            keys.forEach(k => {
                const tr = document.createElement('tr');
                const isExpired = new Date(k.expires_at) < new Date();
                let statusBadge = '<span class="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded text-xs border border-emerald-500/20">Active</span>';
                if (k.is_revoked) {
                    statusBadge = '<span class="text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded text-xs border border-rose-500/20">Revoked</span>';
                } else if (isExpired) {
                    statusBadge = '<span class="text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded text-xs border border-amber-500/20">Expired</span>';
                }

                let revokeBtn = '';
                if (!k.is_revoked) {
                    revokeBtn = '<button onclick="revokeKey(\'' + k.key_code + '\')" class="text-xs bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 px-2.5 py-1 rounded">Revoke</button>';
                }

                tr.innerHTML = '<td class="p-3 font-mono text-slate-500">' + k.id + '</td>' +
                    '<td class="p-3 font-mono text-slate-200 select-all">' + k.key_code + '</td>' +
                    '<td class="p-3 font-semibold text-slate-300">' + k.duration + '</td>' +
                    '<td class="p-3 text-xs">' + new Date(k.expires_at).toLocaleString() + '</td>' +
                    '<td class="p-3">' + statusBadge + '</td>' +
                    '<td class="p-3 text-right">' + revokeBtn + '</td>';
                tbody.appendChild(tr);
            });
        }

        async function revokeKey(key) {
            await fetch('/api/revoke', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ key })
            });
            await loadKeys();
        }

        loadKeys();
    </script>
</body>
</html>
`
