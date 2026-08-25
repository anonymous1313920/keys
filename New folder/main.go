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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const SecretKey = "YourSuperSecretAdminKeyChangeMe"

var db *sql.DB

type KeyRecord struct {
	ID           int            `json:"id"`
	KeyValue     string         `json:"key_value"`
	DurationDays int            `json:"duration_days"`
	IsRevoked    bool           `json:"is_revoked"`
	HWID         sql.NullString `json:"hwid"`
	ActivatedAt  sql.NullTime   `json:"activated_at"`
}

type KeyRequest struct {
	Duration string `json:"duration"`
}

type RevokeRequest struct {
	Key string `json:"key"`
}

func main() {
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("❌ DATABASE_URL environment variable is not set")
	}

	if !strings.Contains(dbURL, "sslmode=") {
		if strings.Contains(dbURL, "?") {
			dbURL += "&sslmode=require"
		} else {
			dbURL += "?sslmode=require"
		}
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("❌ Database connection error: %v", err)
	}

	initDB()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/generate", handleGenerate)
	http.HandleFunc("/api/keys", handleListKeys)
	http.HandleFunc("/api/revoke", handleRevoke)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("🚀 Admin Panel running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func initDB() {
	query := `
	CREATE TABLE IF NOT EXISTS keys (
		id SERIAL PRIMARY KEY,
		key_value VARCHAR(255) UNIQUE NOT NULL,
		duration_days INT NOT NULL DEFAULT 1,
		is_revoked BOOLEAN DEFAULT FALSE,
		hwid VARCHAR(255) DEFAULT NULL,
		activated_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Fix constraints on legacy tables if they exist
	_, _ = db.Exec("ALTER TABLE keys ALTER COLUMN duration DROP NOT NULL;")
	_, _ = db.Exec("ALTER TABLE keys ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;")
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

	var days int
	switch strings.ToUpper(req.Duration) {
	case "DAY":
		days = 1
	case "WEEK":
		days = 7
	case "MONTH":
		days = 30
	default:
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Invalid duration choice"})
		return
	}

	keyValue := GenerateKey(req.Duration, days)

	// Primary Insert: explicitly setting created_at to NOW()
	query := "INSERT INTO keys (key_value, duration_days, created_at) VALUES ($1, $2, NOW())"
	_, err := db.Exec(query, keyValue, days)
	if err != nil {
		// Fallback query for older tables expecting both 'duration' and 'duration_days'
		fallbackQuery := "INSERT INTO keys (key_value, duration, duration_days, created_at) VALUES ($1, $2, $3, NOW())"
		_, err = db.Exec(fallbackQuery, keyValue, days, days)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Failed to save key: " + err.Error()})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"key":           keyValue,
		"duration_days": days,
	})
}

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("SELECT id, key_value, duration_days, is_revoked, hwid, activated_at FROM keys ORDER BY id DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []map[string]any
	for rows.Next() {
		var k KeyRecord
		rows.Scan(&k.ID, &k.KeyValue, &k.DurationDays, &k.IsRevoked, &k.HWID, &k.ActivatedAt)

		hwidStr := "Not Locked"
		if k.HWID.Valid {
			hwidStr = k.HWID.String
		}

		activatedStr := "Unused"
		if k.ActivatedAt.Valid {
			activatedStr = k.ActivatedAt.Time.Format(time.RFC1123)
		}

		keys = append(keys, map[string]any{
			"id":            k.ID,
			"key_value":     k.KeyValue,
			"duration_days": k.DurationDays,
			"is_revoked":    k.IsRevoked,
			"hwid":          hwidStr,
			"activated_at":  activatedStr,
		})
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

	_, err := db.Exec("UPDATE keys SET is_revoked = TRUE WHERE key_value = $1", req.Key)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Database update failed"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func GenerateKey(duration string, days int) string {
	timestampStr := strconv.FormatInt(time.Now().UnixNano(), 10)[:10]
	payload := fmt.Sprintf("%s-%s-%d", strings.ToUpper(duration), timestampStr, days)
	signature := createHMAC(payload, SecretKey)
	return fmt.Sprintf("%s-%s", payload, signature)
}

func createHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))[:8]
}

const indexHTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - PostgreSQL Key Engine</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans">
    <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-8 w-8 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-lg">🔑</div>
                <span class="font-semibold text-lg tracking-tight">KeyGen Server Dashboard</span>
            </div>
            <span class="text-xs font-mono bg-slate-800 text-slate-400 px-3 py-1 rounded-full border border-slate-700">PostgreSQL Engine</span>
        </div>
    </nav>

    <main class="flex-1 max-w-6xl w-full mx-auto px-6 py-10 space-y-8">
        <div id="errorAlert" class="hidden bg-rose-500/10 border border-rose-500/20 text-rose-300 p-4 rounded-xl text-sm">
            <span id="errorText"></span>
        </div>

        <section class="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl max-w-xl">
            <h2 class="text-xl font-bold mb-1 flex items-center gap-2"><span>⚡</span> Generate Key</h2>
            <p class="text-slate-400 text-sm mb-6">Create keys and persist directly to Cloud Database.</p>
            <div class="grid grid-cols-3 gap-3 mb-6">
                <button onclick="setDuration('DAY')" id="btn-DAY" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Day (1d)</button>
                <button onclick="setDuration('WEEK')" id="btn-WEEK" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Week (7d)</button>
                <button onclick="setDuration('MONTH')" id="btn-MONTH" class="dur-btn border border-slate-700 bg-slate-800 text-slate-200 py-3 rounded-xl font-medium text-sm">Month (30d)</button>
            </div>
            <button onclick="generateKey()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-3 rounded-xl transition shadow-lg">Generate & Save</button>
        </section>

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
                            <th class="p-3">Bound HWID</th>
                            <th class="p-3">Activated At</th>
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
            document.getElementById('btn-' + dur).className = 'dur-btn border-indigo-500 bg-indigo-600/10 text-indigo-400 py-3 rounded-xl font-medium text-sm';
        }

        async function generateKey() {
            const alertBox = document.getElementById('errorAlert');
            alertBox.classList.add('hidden');

            try {
                const res = await fetch('/api/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ duration: selectedDuration })
                });

                const data = await res.json();
                if(!data.success) {
                    document.getElementById('errorText').innerText = data.error || 'Failed to generate key';
                    alertBox.classList.remove('hidden');
                    return;
                }

                await loadKeys();
            } catch(err) {
                document.getElementById('errorText').innerText = 'Network error connecting to backend';
                alertBox.classList.remove('hidden');
            }
        }

        async function loadKeys() {
            const res = await fetch('/api/keys');
            const keys = await res.json();
            const tbody = document.getElementById('keys-table-body');
            tbody.innerHTML = '';

            if(!keys || keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-600">No keys saved in database.</td></tr>';
                return;
            }

            keys.forEach(k => {
                const tr = document.createElement('tr');
                let statusBadge = '<span class="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded text-xs border border-emerald-500/20">Active</span>';
                if (k.is_revoked) {
                    statusBadge = '<span class="text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded text-xs border border-rose-500/20">Revoked</span>';
                }

                let revokeBtn = '';
                if (!k.is_revoked) {
                    revokeBtn = '<button onclick="revokeKey(\'' + k.key_value + '\')" class="text-xs bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 px-2.5 py-1 rounded">Revoke</button>';
                }

                tr.innerHTML = '<td class="p-3 font-mono text-slate-500">' + k.id + '</td>' +
                    '<td class="p-3 font-mono text-slate-200 select-all">' + k.key_value + '</td>' +
                    '<td class="p-3 font-semibold text-slate-300">' + k.duration_days + ' Days</td>' +
                    '<td class="p-3 font-mono text-xs text-slate-400">' + k.hwid + '</td>' +
                    '<td class="p-3 text-xs">' + k.activated_at + '</td>' +
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