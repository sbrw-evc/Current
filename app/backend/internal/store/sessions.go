package store

import (
	"context"
	"time"
)

// Session is a sign-in session. The cookie value itself is never stored, only its keyed hash.
type Session struct {
	IDHash   string
	UserID   int64
	Remote   string
	Created  time.Time
	LastSeen time.Time
}

func (s *Store) CreateSession(ctx context.Context, ss Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (id_hash, user_id, remote, created_at, last_seen) VALUES ($1, $2, $3, $4, $5)`,
		ss.IDHash, ss.UserID, ss.Remote, ss.Created, ss.LastSeen)
	return pgErr(err)
}

func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var ss Session
	err := s.pool.QueryRow(ctx, `SELECT id_hash, user_id, remote, created_at, last_seen FROM sessions WHERE id_hash = $1`, idHash).
		Scan(&ss.IDHash, &ss.UserID, &ss.Remote, &ss.Created, &ss.LastSeen)
	return ss, pgErr(err)
}

func (s *Store) TouchSession(ctx context.Context, idHash string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen = $2 WHERE id_hash = $1`, idHash, at)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
	return err
}

// DeleteUserSessions signs the user out everywhere except the session keepHash ("" = everywhere).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keepHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2`, userID, keepHash)
	return err
}

// PurgeSessions deletes sessions idle since before idleBefore or created before createdBefore.
func (s *Store) PurgeSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE last_seen < $1 OR created_at < $2`, idleBefore, createdBefore)
	return tag.RowsAffected(), err
}
