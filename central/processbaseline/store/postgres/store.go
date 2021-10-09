// Code generated by pg-bindings generator. DO NOT EDIT.

package postgres

import (
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"database/sql"
	"encoding/json"
	"github.com/lib/pq"
	"github.com/stackrox/rox/pkg/set"
)

var (
	log = logging.LoggerForModule()

	table = "processWhitelists2"
)

type Store interface {
	Count() (int, error)
	Exists(id string) (bool, error)
	GetIDs() ([]string, error)
	Get(id string) (*storage.ProcessBaseline, bool, error)
	GetMany(ids []string) ([]*storage.ProcessBaseline, []int, error)
	Upsert(obj *storage.ProcessBaseline) error
	UpsertMany(objs []*storage.ProcessBaseline) error
	Delete(id string) error
	DeleteMany(ids []string) error
	Walk(fn func(obj *storage.ProcessBaseline) error) error
	AckKeysIndexed(keys ...string) error
	GetKeysToIndex() ([]string, error)
}

type storeImpl struct {
	db *sql.DB

	countStmt *sql.Stmt
	existsStmt *sql.Stmt
	getIDsStmt *sql.Stmt
	getStmt *sql.Stmt
	getManyStmt *sql.Stmt
	upsertWithIDStmt *sql.Stmt
	upsertStmt *sql.Stmt
	deleteStmt *sql.Stmt
	deleteManyStmt *sql.Stmt
	walkStmt *sql.Stmt
	walkWithIDStmt *sql.Stmt
}

func alloc() proto.Message {
	return &storage.ProcessBaseline{}
}

func keyFunc(msg proto.Message) string {
	return msg.(*storage.ProcessBaseline).GetId()
}

func compileStmtOrPanic(db *sql.DB, query string) *sql.Stmt {
	vulnStmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	return vulnStmt
}

const createTableQuery = "create table if not exists processWhitelists2 (id varchar primary key, value jsonb)"

// New returns a new Store instance using the provided sql instance.
func New(db *sql.DB) Store {
	globaldb.RegisterTable(table, "ProcessBaseline")

	_, err := db.Exec(createTableQuery)
	if err != nil {
		panic("error creating table")
	}

//
	return &storeImpl{
		db: db,

		countStmt: compileStmtOrPanic(db, "select count(*) from processWhitelists2"),
		existsStmt: compileStmtOrPanic(db, "select exists(select 1 from processWhitelists2 where id = $1)"),
		getIDsStmt: compileStmtOrPanic(db, "select id from processWhitelists2"),
		getStmt: compileStmtOrPanic(db, "select value from processWhitelists2 where id = $1"),
		getManyStmt: compileStmtOrPanic(db, "select value from processWhitelists2 where id = ANY($1::text[])"),
		upsertStmt: compileStmtOrPanic(db, "insert into processWhitelists2(id, value) values($1, $2) on conflict(id) do update set value=$2"),
		deleteStmt: compileStmtOrPanic(db, "delete from processWhitelists2 where id = $1"),
		deleteManyStmt: compileStmtOrPanic(db, "delete from processWhitelists2 where id = ANY($1::text[])"),
		walkStmt: compileStmtOrPanic(db, "select value from processWhitelists2"),
		walkWithIDStmt: compileStmtOrPanic(db, "select id, value from processWhitelists2"),
	}
//
}

// Count returns the number of objects in the store
func (s *storeImpl) Count() (int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Count, "ProcessBaseline")

	row := s.countStmt.QueryRow()
	if err := row.Err(); err != nil {
		return 0, err
	}
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Exists returns if the id exists in the store
func (s *storeImpl) Exists(id string) (bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Exists, "ProcessBaseline")

	row := s.existsStmt.QueryRow(id)
	if err := row.Err(); err != nil {
		return false, nilNoRows(err)
	}
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, nilNoRows(err)
	}
	return exists, nil
}

// GetIDs returns all the IDs for the store
func (s *storeImpl) GetIDs() ([]string, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetAll, "ProcessBaselineIDs")

	rows, err := s.getIDsStmt.Query()
	if err != nil {
		return nil, nilNoRows(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func nilNoRows(err error) error {
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(id string) (*storage.ProcessBaseline, bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Get, "ProcessBaseline")

	t := time.Now()
	row := s.getStmt.QueryRow(id)
	if err := row.Err(); err != nil {
		return nil, false, nilNoRows(err)
	}
	log.Infof("Took %d to query a ProcessBaseline", time.Since(t).Milliseconds())

	var data []byte
	t = time.Now()
	if err := row.Scan(&data); err != nil {
		return nil, false, nilNoRows(err)
	}
	log.Infof("Took %d to scan a ProcessBaseline", time.Since(t).Milliseconds())

	msg := alloc()
	t = time.Now()
	if err := json.Unmarshal(data, msg); err != nil {
		return nil, false, err
	}
	log.Infof("Took %d to unmarshal a ProcessBaseline", time.Since(t).Milliseconds())
	return msg.(*storage.ProcessBaseline), true, nil
}

// GetMany returns the objects specified by the IDs or the index in the missing indices slice 
func (s *storeImpl) GetMany(ids []string) ([]*storage.ProcessBaseline, []int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetMany, "ProcessBaseline")

	rows, err := s.getManyStmt.Query(pq.Array(ids))
	if err != nil {
		if err == sql.ErrNoRows {
			missingIndices := make([]int, 0, len(ids))
			for i := range ids {
				missingIndices = append(missingIndices, i)
			}
			return nil, missingIndices, nil
		}
		return nil, nil, err
	}
	defer rows.Close()
	elems := make([]*storage.ProcessBaseline, 0, len(ids))
	foundSet := set.NewStringSet()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, nil, err
		}
		msg := alloc()
		if err := json.Unmarshal(data, msg); err != nil {
			return nil, nil, err
		}
		elem := msg.(*storage.ProcessBaseline)
		foundSet.Add(elem.GetId())
		elems = append(elems, elem)
	}
	missingIndices := make([]int, 0, len(ids)-len(foundSet))
	for i, id := range ids {
		if !foundSet.Contains(id) {
			missingIndices = append(missingIndices, i)
		}
	}
	return elems, missingIndices, nil
}

func (s *storeImpl) upsert(id string, obj *storage.ProcessBaseline) error {
	value, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = s.upsertStmt.Exec(id, value)
	return err
}


// Upsert inserts the object into the DB
func (s *storeImpl) Upsert(obj *storage.ProcessBaseline) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Add, "ProcessBaseline")
	return s.upsert(keyFunc(obj), obj)
}

// UpsertMany batches objects into the DB
func (s *storeImpl) UpsertMany(objs []*storage.ProcessBaseline) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.AddMany, "ProcessBaseline")

	// Txn? or all errors to be passed through?
	for _, obj := range objs {
		if err := s.upsert(keyFunc(obj), obj); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the specified ID from the store
func (s *storeImpl) Delete(id string) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Remove, "ProcessBaseline")

	if _, err := s.deleteStmt.Exec(id); err != nil {
		return err
	}
	return nil
}

// Delete removes the specified IDs from the store
func (s *storeImpl) DeleteMany(ids []string) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.RemoveMany, "ProcessBaseline")

	if _, err := s.deleteManyStmt.Exec(pq.Array(ids)); err != nil {
		return err
	}
	return nil
}

// Walk iterates over all of the objects in the store and applies the closure
func (s *storeImpl) Walk(fn func(obj *storage.ProcessBaseline) error) error {
	rows, err := s.walkStmt.Query()
	if err != nil {
		return nilNoRows(err)
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		msg := alloc()
		if err := json.Unmarshal(data, msg); err != nil {
			return err
		}
		return fn(msg.(*storage.ProcessBaseline))
	}
	return nil
}

// AckKeysIndexed acknowledges the passed keys were indexed
func (s *storeImpl) AckKeysIndexed(keys ...string) error {
	return nil
}

// GetKeysToIndex returns the keys that need to be indexed
func (s *storeImpl) GetKeysToIndex() ([]string, error) {
	return nil, nil
}
