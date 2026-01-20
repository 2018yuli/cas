package app

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll("data", 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			disabled BOOLEAN NOT NULL DEFAULT 0,
			locked_until TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE
		);`,
		`CREATE TABLE IF NOT EXISTS user_roles (
			user_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, role_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS webtops (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			target_url TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT 1
		);`,
		`CREATE TABLE IF NOT EXISTS role_webtops (
			role_id INTEGER NOT NULL,
			webtop_id INTEGER NOT NULL,
			PRIMARY KEY (role_id, webtop_id),
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
			FOREIGN KEY (webtop_id) REFERENCES webtops(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			success BOOLEAN NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time ON login_attempts(user_id, attempted_at DESC);`,
	}
	for _, stmt := range schema {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) EnsureDefaults() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	adminRoleID, err := s.ensureRoleTx(tx, defaultAdminRole)
	if err != nil {
		return err
	}
	userRoleID, err := s.ensureRoleTx(tx, "user")
	if err != nil {
		return err
	}

	var userID int64
	err = tx.QueryRow(`SELECT id FROM users WHERE username = ?`, defaultAdminUser).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		hash, _ := bcrypt.GenerateFromPassword([]byte(defaultAdminPassword), bcryptCost)
		res, err := tx.Exec(`INSERT INTO users(username, password_hash) VALUES(?, ?)`, defaultAdminUser, string(hash))
		if err != nil {
			return err
		}
		userID, _ = res.LastInsertId()
		log.Printf("created default admin user: %s / %s", defaultAdminUser, defaultAdminPassword)
	} else if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)`, userID, adminRoleID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)`, userID, userRoleID); err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM webtops`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		defaultWebtops := []struct {
			Name string
			URL  string
		}{
			{"webtop-1", "http://webtop1:3000"},
			{"webtop-2", "http://webtop2:3000"},
			{"webtop-3", "http://webtop3:3000"},
		}
		for _, w := range defaultWebtops {
			res, err := tx.Exec(`INSERT INTO webtops(name, target_url) VALUES(?, ?)`, w.Name, w.URL)
			if err != nil {
				return err
			}
			wid, _ := res.LastInsertId()
			if _, err := tx.Exec(`INSERT OR IGNORE INTO role_webtops(role_id, webtop_id) VALUES(?, ?)`, adminRoleID, wid); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO role_webtops(role_id, webtop_id) VALUES(?, ?)`, userRoleID, wid); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) ensureRoleTx(tx *sql.Tx, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM roles WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		res, err := tx.Exec(`INSERT INTO roles(name) VALUES(?)`, name)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	return id, err
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, username, password_hash, disabled, locked_until FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.Password, &u.Disabled, &u.LockedUntil)
	return u, err
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, disabled, locked_until FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Disabled, &u.LockedUntil); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func (s *Store) SetUserPassword(userID int64, plain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), userID)
	return err
}

func (s *Store) SetUserDisabled(userID int64, disabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, disabled, userID)
	return err
}

func (s *Store) EnsureUserWithRole(username, password string, roles []string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var id int64
	err = tx.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			return 0, err
		}
		res, err := tx.Exec(`INSERT INTO users(username, password_hash) VALUES(?, ?)`, username, string(hash))
		if err != nil {
			return 0, err
		}
		id, _ = res.LastInsertId()
	} else if err != nil {
		return 0, err
	}

	for _, role := range roles {
		roleID, err := s.ensureRoleTx(tx, role)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)`, id, roleID); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *Store) HasRole(userID int64, role string) (bool, error) {
	var cnt int
	err := s.db.QueryRow(`
		SELECT COUNT(1)
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.name = ?`, userID, role).Scan(&cnt)
	return cnt > 0, err
}

func (s *Store) RecordAttempt(userID int64, success bool) error {
	_, err := s.db.Exec(`INSERT INTO login_attempts(user_id, success) VALUES(?, ?)`, userID, success)
	return err
}

func (s *Store) RecordFailureAndMaybeLock(userID int64) (*time.Time, error) {
	rows, err := s.db.Query(`SELECT success, attempted_at FROM login_attempts WHERE user_id = ? ORDER BY attempted_at DESC LIMIT 20`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	failures := 0
	for rows.Next() {
		var success bool
		var t time.Time
		if err := rows.Scan(&success, &t); err != nil {
			return nil, err
		}
		if success {
			break
		}
		failures++
	}
	failures++

	var lockUntil *time.Time
	if failures >= 3 {
		multiplier := failures - 3
		if multiplier > 20 {
			multiplier = 20
		}
		d := baseLockDuration * time.Duration(1<<multiplier)
		if d > maxLockDuration {
			d = maxLockDuration
		}
		t := time.Now().Add(d)
		lockUntil = &t
		if _, err := s.db.Exec(`UPDATE users SET locked_until = ? WHERE id = ?`, t, userID); err != nil {
			return nil, err
		}
	}
	if err := s.RecordAttempt(userID, false); err != nil {
		return lockUntil, err
	}
	return lockUntil, nil
}

func (s *Store) ClearLock(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET locked_until = NULL WHERE id = ?`, userID)
	return err
}

func (s *Store) CreateSession(userID int64, expires time.Time) (string, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(`INSERT INTO sessions(id, user_id, expires_at) VALUES(?, ?, ?)`, id, userID, expires)
	return id, err
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) SessionUser(id string) (User, time.Time, error) {
	var u User
	var exp time.Time
	err := s.db.QueryRow(`
		SELECT s.expires_at, u.id, u.username, u.password_hash, u.disabled, u.locked_until
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id = ?`, id).Scan(&exp, &u.ID, &u.Username, &u.Password, &u.Disabled, &u.LockedUntil)
	return u, exp, err
}

func (s *Store) ListWebtopsForUser(userID int64) ([]Webtop, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT w.id, w.name, w.target_url, w.enabled
		FROM webtops w
		JOIN role_webtops rw ON rw.webtop_id = w.id
		JOIN user_roles ur ON ur.role_id = rw.role_id
		WHERE ur.user_id = ? AND w.enabled = 1
		ORDER BY w.id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webtop
	for rows.Next() {
		var w Webtop
		if err := rows.Scan(&w.ID, &w.Name, &w.TargetURL, &w.Enabled); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

func (s *Store) GetWebtop(id int64, userID int64) (Webtop, error) {
	var w Webtop
	err := s.db.QueryRow(`
		SELECT DISTINCT w.id, w.name, w.target_url, w.enabled
		FROM webtops w
		JOIN role_webtops rw ON rw.webtop_id = w.id
		JOIN user_roles ur ON ur.role_id = rw.role_id
		WHERE w.id = ? AND ur.user_id = ? AND w.enabled = 1
	`, id, userID).Scan(&w.ID, &w.Name, &w.TargetURL, &w.Enabled)
	return w, err
}

func (s *Store) ListWebtops() ([]Webtop, error) {
	rows, err := s.db.Query(`SELECT id, name, target_url, enabled FROM webtops ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webtop
	for rows.Next() {
		var w Webtop
		if err := rows.Scan(&w.ID, &w.Name, &w.TargetURL, &w.Enabled); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

func (s *Store) CreateWebtop(name, url string, enabled bool) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO webtops(name, target_url, enabled) VALUES(?, ?, ?)`, name, url, enabled)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	// Attach to admin and user roles by default
	for _, role := range []string{defaultAdminRole, "user"} {
		rid, err := s.ensureRoleTx(tx, role)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO role_webtops(role_id, webtop_id) VALUES(?, ?)`, rid, id); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *Store) UpdateWebtop(id int64, name, target string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE webtops SET name = ?, target_url = ?, enabled = ? WHERE id = ?`, name, target, enabled, id)
	return err
}

func (s *Store) DeleteWebtop(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM role_webtops WHERE webtop_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM webtops WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplaceWebtops(webtops []Webtop) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	adminRoleID, err := s.ensureRoleTx(tx, defaultAdminRole)
	if err != nil {
		return err
	}
	userRoleID, err := s.ensureRoleTx(tx, "user")
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM role_webtops`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM webtops`); err != nil {
		return err
	}

	for _, w := range webtops {
		res, err := tx.Exec(`INSERT INTO webtops(name, target_url, enabled) VALUES(?, ?, ?)`, w.Name, w.TargetURL, w.Enabled)
		if err != nil {
			return err
		}
		wid, _ := res.LastInsertId()
		if _, err := tx.Exec(`INSERT OR IGNORE INTO role_webtops(role_id, webtop_id) VALUES(?, ?)`, adminRoleID, wid); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO role_webtops(role_id, webtop_id) VALUES(?, ?)`, userRoleID, wid); err != nil {
			return err
		}
	}
	return tx.Commit()
}
