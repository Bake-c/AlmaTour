// ===============================
//      ALMATOUR BACKEND SERVER
// ===============================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3000;

// -------------------------------
// 1. DATABASE (SQLite)
// -------------------------------
const db = new sqlite3.Database('./users.db');

// Создание таблицы, если нет
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT NOT NULL
    )
`);

// -------------------------------
// 2. MIDDLEWARE
// -------------------------------
app.use(express.json());

// Раздача твоего сайта
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------
// 3. REGISTER
// -------------------------------
app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password || password.length < 1) {
        return res.status(400).json({
            ok: false,
            message: "Invalid username or password"
        });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        const sql = `INSERT INTO users (username, password_hash) VALUES (?, ?)`;

        db.run(sql, [username, passwordHash], function (err) {
            if (err) {
                if (err.code === "SQLITE_CONSTRAINT") {
                    return res.status(400).json({
                        ok: false,
                        message: "This username is already taken"
                    });
                }
                return res.status(500).json({
                    ok: false,
                    message: "Database error"
                });
            }

            return res.json({ ok: true });
        });

    } catch (error) {
        return res.status(500).json({
            ok: false,
            message: "Server error"
        });
    }
});

// -------------------------------
// 4. LOGIN
// -------------------------------
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [username], async (err, row) => {
        if (err) {
            return res.status(500).json({
                ok: false,
                message: "Database error"
            });
        }

        if (!row) {
            return res.status(400).json({
                ok: false,
                message: "Invalid username or password"
            });
        }

        const valid = await bcrypt.compare(password, row.password_hash);

        if (!valid) {
            return res.status(400).json({
                ok: false,
                message: "Invalid username or password"
            });
        }

        return res.json({ ok: true });
    });
});

// -------------------------------
// 5. START SERVER
// -------------------------------
app.listen(PORT, () => {
    console.log(`🔥 Server running on http://localhost:${PORT}`);
});
