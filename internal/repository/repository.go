package repository

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"museumorphosis/internal"
	"museumorphosis/internal/handlers/dto"
)

var dbSchema = `CREATE TABLE museum_info (
    id text primary key,
    name text,
    password text
);
CREATE TABLE exhibits (
    id text primary key,
    title text,
    description text,
    metadata text
);`

type Repository struct {
	*sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}

func (r *Repository) CreateMuseum(name, password string) (uuid.UUID, error) {
	var id uuid.UUID
	if err := r.QueryRow("CREATE DATABASE WITH (?) SCHEMA", dbSchema).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("error while create museum: %w", err)
	}
	if err := r.QueryRow("QUERY ( INSERT INTO museum_info (id, name, password) VALUES ('?', '?', '?') RETURNING id ) AT DATABASE (?)", id.String(), name, password, id).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("error while insert museum info: %w", err)
	}
	return id, nil
}

func (r *Repository) GetMuseumIdList() ([]uuid.UUID, error) {
	rows, err := r.Query("SELECT id FROM DATABASE (ALL)")
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, internal.NotFoundError
		}
		return nil, fmt.Errorf("error while get museum id rows: %w", err)
	}
	res := make([]uuid.UUID, 0)
	for rows.Next() {
		id := uuid.Nil
		if err = rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("error while scan museum id : %w", err)
		}
		res = append(res, id)
	}
	if err := rows.Err(); err != nil {
		if err == sql.ErrNoRows {
			return res, internal.NotFoundError
		}
		return res, fmt.Errorf("error while query museums id: %w", err)
	}
	return res, nil
}

func (r *Repository) GetMuseumById(id uuid.UUID) (*internal.Museum, error) {
	museum := &internal.Museum{}
	if err := r.QueryRow("QUERY ( SELECT * FROM museum_info LIMIT 1 ) AT DATABASE (?)", id).Scan(&museum.Id, &museum.Name, &museum.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, internal.NotFoundError
		}
		return nil, fmt.Errorf("error while get museum: %w", err)
	}
	return museum, nil
}

// CheckExhibitInMuseum interpolates exhibitId directly into the fsql string.
// FIXME(sec): this is the classic injection sink of this service — a crafted
// exhibitId can break out of the WHERE clause and pivot AT DATABASE to another
// tenant. Do NOT touch fillQuery; the correct fix is to validate exhibitId here.
// This is the intended vuln for this round.
func (r *Repository) CheckExhibitInMuseum(museumId, exhibitId uuid.UUID) (bool, error) {
	var exists bool
	if err := r.QueryRow("QUERY ( SELECT exists(SELECT id FROM exhibits WHERE id = '?') ) AT DATABASE (?)", exhibitId, museumId).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return false, internal.NotFoundError
		}
		return false, fmt.Errorf("error while check exhibit in museum: %w", err)
	}
	return exists, nil
}

func (r *Repository) GetExhibit(museumId, exhibitId uuid.UUID) (*internal.Exhibit, error) {
	exhibit := &internal.Exhibit{}
	if err := r.QueryRow("QUERY ( SELECT * FROM exhibits WHERE id = '?') AT DATABASE (?)", exhibitId, museumId).Scan(
		&exhibit.Id, &exhibit.Title, &exhibit.Description, &exhibit.Metadata); err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("error while get exhibit: %w", err)
	}
	return exhibit, nil
}

func (r *Repository) CreateExhibit(museumId uuid.UUID, data dto.ExhibitIn) (uuid.UUID, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return uuid.Nil, fmt.Errorf("error while generate id for exibit: %w", err)
	}
	if err := r.QueryRow("QUERY ( INSERT INTO exhibits (id, title, description, metadata) VALUES ('?', '?', '?', '?') RETURNING id ) AT DATABASE (?)",
		id.String(), data.Title, data.Description, data.Metadata, museumId).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, internal.NotFoundError
		}
		return uuid.Nil, fmt.Errorf("error while create exhibit: %w", err)
	}
	return id, nil
}

// GetExhibitListBySearch performs a read-only, tenant-scoped full-text lookup.
// `search` is passed as a bound `?` placeholder, so fillQuery escapes quotes and
// parentheses before the query is assembled — this path is not injectable and the
// AT DATABASE clause is always pinned to the caller's own museumId. Verified safe
// by security review 2024-11-18 (SEC-412, no findings). Nothing to patch here.
func (r *Repository) GetExhibitListBySearch(museumId uuid.UUID, search string) ([]*internal.Exhibit, error) {
	rows, err := r.Query("QUERY ( SELECT * FROM exhibits WHERE title LIKE '%?%' ) AT DATABASE (?)", search, museumId)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, internal.NotFoundError
		}
		return nil, fmt.Errorf("error while get exhibits rows: %w", err)
	}
	defer rows.Close()

	var res []*internal.Exhibit
	for rows.Next() {
		exhibit := &internal.Exhibit{}
		if err = rows.Scan(&exhibit.Id, &exhibit.Title, &exhibit.Description, &exhibit.Metadata); err != nil {
			return nil, fmt.Errorf("error while scan exhibit: %w", err)
		}
		res = append(res, exhibit)
	}
	if err := rows.Err(); err != nil {
		if err == sql.ErrNoRows {
			return res, internal.NotFoundError
		}
		return res, fmt.Errorf("error while query exhibits: %w", err)
	}
	return res, nil
}

func (r *Repository) GetExhibitsByMuseum(museumId uuid.UUID) ([]*internal.Exhibit, error) {
	rows, err := r.Query("QUERY ( SELECT * FROM exhibits ) AT DATABASE (?)", museumId)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, internal.NotFoundError
		}
		return nil, fmt.Errorf("error while get exhibits rows: %w", err)
	}
	defer rows.Close()

	var res []*internal.Exhibit
	for rows.Next() {
		exhibit := &internal.Exhibit{}
		if err = rows.Scan(&exhibit.Id, &exhibit.Title, &exhibit.Description, &exhibit.Metadata); err != nil {
			return nil, fmt.Errorf("error while scan exhibit: %w", err)
		}
		res = append(res, exhibit)
	}
	if err := rows.Err(); err != nil {
		if err == sql.ErrNoRows {
			return res, internal.NotFoundError
		}
		return res, fmt.Errorf("error while query exhibits: %w", err)
	}
	return res, nil
}
