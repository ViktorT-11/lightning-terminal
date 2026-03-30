package accounts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

const (
	// dbFilePermission is the default permission the account database file
	// is created with.
	dbFilePermission = 0600
)

var (
	// ErrKVDBDeprecated signals that the legacy kvdb database was already
	// migrated to SQL and should not be opened again.
	ErrKVDBDeprecated = errors.New("kvdb database has been migrated to " +
		"SQL and can no longer be used")

	// deprecatedBucketKey marks a kvdb database as deprecated in a way that
	// older kvdb account readers will fail once they iterate the account
	// bucket.
	deprecatedBucketKey = []byte("kvdb-sql-migrated")

	deprecatedReasonKey = []byte("reason")
)

// DeprecateKVDB marks the accounts kvdb file as deprecated after a successful
// SQL migration.
func DeprecateKVDB(path string) error {
	db, err := bbolt.Open(path, dbFilePermission, &bbolt.Options{
		Timeout: DefaultAccountDBTimeout,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		accountBucket, err := tx.CreateBucketIfNotExists(
			accountBucketName,
		)
		if err != nil {
			return err
		}

		deprecatedBucket, err := accountBucket.CreateBucketIfNotExists(
			deprecatedBucketKey,
		)
		if err != nil {
			return err
		}

		return deprecatedBucket.Put(
			deprecatedReasonKey, []byte(ErrKVDBDeprecated.Error()),
		)
	})
}

// RemoveKVDBDeprecation removes the accounts kvdb deprecation marker.
func RemoveKVDBDeprecation(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	db, err := bbolt.Open(path, dbFilePermission, &bbolt.Options{
		Timeout: DefaultAccountDBTimeout,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		accountBucket := tx.Bucket(accountBucketName)
		if accountBucket == nil {
			return nil
		}

		if accountBucket.Bucket(deprecatedBucketKey) == nil {
			return nil
		}

		return accountBucket.DeleteBucket(deprecatedBucketKey)
	})
}

// CheckKVDBDeprecated returns a clear error if the accounts kvdb file was
// marked as deprecated.
func CheckKVDBDeprecated(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	db, err := bbolt.Open(path, dbFilePermission, &bbolt.Options{
		Timeout: DefaultAccountDBTimeout,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	var deprecated bool
	err = db.View(func(tx *bbolt.Tx) error {
		accountBucket := tx.Bucket(accountBucketName)
		if accountBucket == nil {
			return nil
		}

		deprecated = accountBucket.Bucket(deprecatedBucketKey) != nil
		return nil
	})
	if err != nil {
		return err
	}

	if deprecated {
		return fmt.Errorf("%w: %s", ErrKVDBDeprecated, filepath.Base(path))
	}

	return nil
}
