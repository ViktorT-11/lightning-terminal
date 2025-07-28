package firewalldb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lightninglabs/lightning-terminal/accounts"
	"github.com/lightninglabs/lightning-terminal/db/sqlc"
	"github.com/lightninglabs/lightning-terminal/session"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/sqldb"
	"go.etcd.io/bbolt"
	"sort"
)

// kvEntry represents a single KV entry inserted into the BoltDB.
type kvEntry struct {
	perm     bool
	ruleName string
	key      string
	value    []byte

	// groupAlias is the legacy session group alias that the entry is
	// associated with. For global entries, this will be fn.None[[]byte].
	groupAlias fn.Option[[]byte]

	// featureName is the name of the feature that the entry is associated
	// with. If the entry is not feature specific, this will be
	// fn.None[string].
	featureName fn.Option[string]
}

// sqlKvEntry represents a single KV entry inserted into the SQL DB, containing
// the same fields as the kvEntry, but with additional fields that represent the
// SQL IDs of the rule, session group, and feature.
type sqlKvEntry struct {
	*kvEntry

	ruleID int64

	// groupID is the sql session group ID that the entry is associated
	// with. For global entries, this will be Valid=false.
	groupID sql.NullInt64

	// featureID is the sql feature ID that the entry is associated with.
	// This is only set if the entry is feature specific, and will be
	// Valid=false for other types entries. If this is set, then groupID
	// will also be set.
	featureID sql.NullInt64
}

// namespacedKey returns a string representation of the kvEntry purely used for
// logging purposes.
func (e *kvEntry) namespacedKey() string {
	ns := fmt.Sprintf("perm: %t, rule: %s", e.perm, e.ruleName)

	e.groupAlias.WhenSome(func(alias []byte) {
		ns += fmt.Sprintf(", group: %s", alias)
	})

	e.featureName.WhenSome(func(feature string) {
		ns += fmt.Sprintf(", feature: %s", feature)
	})

	ns += fmt.Sprintf(", key: %s", e.key)

	return ns
}

// privacyPairs is a type alias for a map that holds the privacy pairs, where
// the outer key is the group ID, and the value is a map of real to pseudo
// values.
type privacyPairs = map[int64]map[string]string

// MigrateFirewallDBToSQL runs the migration of the firwalldb stores from the
// bbolt database to a SQL database. The migration is done in a single
// transaction to ensure that all rows in the stores are migrated or none at
// all.
//
// NOTE: As sessions may contain linked sessions and accounts, the sessions and
// accounts sql migration MUST be run prior to this migration.
func MigrateFirewallDBToSQL(ctx context.Context, kvStore *bbolt.DB,
	sqlTx SQLQueries, sessionDB session.SQLQueries,
	accountDB accounts.SQLQueries) error {

	log.Infof("Starting migration of the rules DB to SQL")

	err := migrateKVStoresDBToSQL(ctx, kvStore, sqlTx)
	if err != nil {
		return err
	}

	err = migratePrivacyMapperDBToSQL(ctx, kvStore, sqlTx)
	if err != nil {
		return err
	}

	err = migrateActionsToSQL(
		ctx, kvStore, sqlTx, sessionDB, accountDB, nil,
	)
	if err != nil {
		return err
	}

	log.Infof("The rules DB has been migrated from KV to SQL.")

	return nil
}

// migrateKVStoresDBToSQL runs the migration of all KV stores from the KV
// database to the SQL database. The function also asserts that the
// migrated values match the original values in the KV store.
func migrateKVStoresDBToSQL(ctx context.Context, kvStore *bbolt.DB,
	sqlTx SQLQueries) error {

	log.Infof("Starting migration of the KV stores to SQL")

	var pairs []*kvEntry

	// 1) Collect all key-value pairs from the KV store.
	err := kvStore.View(func(tx *bbolt.Tx) error {
		var err error
		pairs, err = collectAllPairs(tx)
		return err
	})
	if err != nil {
		return fmt.Errorf("collecting all kv pairs failed: %w", err)
	}

	var insertedPairs []*sqlKvEntry

	// 2) Insert all collected key-value pairs into the SQL database.
	for _, entry := range pairs {
		insertedPair, err := insertPair(ctx, sqlTx, entry)
		if err != nil {
			return fmt.Errorf("inserting kv pair %v failed: %w",
				entry.key, err)
		}

		insertedPairs = append(insertedPairs, insertedPair)
	}

	// 3) Validate the migrated values against the original values.
	for _, insertedPair := range insertedPairs {
		// Fetch the appropriate SQL entry's value.
		migratedValue, err := getSQLValue(ctx, sqlTx, insertedPair)
		if err != nil {
			return fmt.Errorf("getting SQL value for key %s "+
				"failed: %w", insertedPair.namespacedKey(), err)
		}

		// Compare the value of the migrated entry with the original
		// value from the KV store.
		// NOTE: if the insert a []byte{} value into the sqldb as the
		// entry value, and then retrieve it, the value will be
		// returned as nil. The bytes.Equal will pass in that case,
		// and therefore such cases won't error out. The kvdb instance
		// can store []byte{} values.
		if !bytes.Equal(migratedValue, insertedPair.value) {
			return fmt.Errorf("migrated value for key %s "+
				"does not match original value: "+
				"migrated %x, original %x",
				insertedPair.namespacedKey(), migratedValue,
				insertedPair.value)
		}
	}

	log.Infof("Migration of the KV stores to SQL completed. Total number "+
		"of rows migrated: %d", len(pairs))

	return nil
}

// collectAllPairs collects all key-value pairs from the KV store, and returns
// them as a slice of kvEntry structs. The function expects the KV store to be
// stuctured as described in the comment in the firewalldb/kvstores_kvdb.go
// file. Any other structure will result in an error.
// Note that this function and the subsequent functions are intentionally
// designed to iterate over all buckets and values that exist in the KV store.
// That ensures that we find all stores and values that exist in the KV store,
// and can be sure that the kv store actually follows the expected structure.
func collectAllPairs(tx *bbolt.Tx) ([]*kvEntry, error) {
	var entries []*kvEntry
	for _, perm := range []bool{true, false} {
		mainBucket, err := getMainBucket(tx, false, perm)
		if err != nil {
			return nil, err
		}

		if mainBucket == nil {
			// If the mainBucket doesn't exist, there are no entries
			// to migrate under that bucket, therefore we don't
			// error, and just proceed to not migrate any entries
			// under that bucket.
			continue
		}

		// Loop over each rule-name bucket.
		err = mainBucket.ForEach(func(rule, v []byte) error {
			if v != nil {
				return errors.New("expected only " +
					"buckets under main bucket")
			}

			ruleBucket := mainBucket.Bucket(rule)
			if ruleBucket == nil {
				return fmt.Errorf("rule bucket %s not found",
					rule)
			}

			pairs, err := collectRulePairs(
				ruleBucket, perm, string(rule),
			)
			if err != nil {
				return err
			}

			entries = append(entries, pairs...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// collectRulePairs processes a single rule bucket, which should contain the
// global and session-kv-store key buckets.
func collectRulePairs(bkt *bbolt.Bucket, perm bool, rule string) ([]*kvEntry,
	error) {

	var params []*kvEntry

	err := verifyBktKeys(
		bkt, true, globalKVStoreBucketKey, sessKVStoreBucketKey,
	)
	if err != nil {
		return params, fmt.Errorf("verifying rule bucket %s keys "+
			"failed: %w", rule, err)
	}

	if globalBkt := bkt.Bucket(globalKVStoreBucketKey); globalBkt != nil {
		p, err := collectKVPairs(
			globalBkt, true, perm, rule,
			fn.None[[]byte](), fn.None[string](),
		)
		if err != nil {
			return nil, fmt.Errorf("collecting global kv pairs "+
				"failed: %w", err)
		}

		params = append(params, p...)
	}

	if sessBkt := bkt.Bucket(sessKVStoreBucketKey); sessBkt != nil {
		err := sessBkt.ForEach(func(groupAlias, v []byte) error {
			if v != nil {
				return fmt.Errorf("expected only buckets "+
					"under %s bucket", sessKVStoreBucketKey)
			}

			groupBucket := sessBkt.Bucket(groupAlias)
			if groupBucket == nil {
				return fmt.Errorf("group bucket for group "+
					"alias %s not found", groupAlias)
			}

			kvPairs, err := collectKVPairs(
				groupBucket, false, perm, rule,
				fn.Some(groupAlias), fn.None[string](),
			)
			if err != nil {
				return fmt.Errorf("collecting group kv "+
					"pairs failed: %w", err)
			}

			params = append(params, kvPairs...)

			err = verifyBktKeys(
				groupBucket, false, featureKVStoreBucketKey,
			)
			if err != nil {
				return fmt.Errorf("verification of group "+
					"bucket %s keys failed: %w", groupAlias,
					err)
			}

			ftBkt := groupBucket.Bucket(featureKVStoreBucketKey)
			if ftBkt == nil {
				return nil
			}

			return ftBkt.ForEach(func(ftName, v []byte) error {
				if v != nil {
					return fmt.Errorf("expected only "+
						"buckets under %s bucket",
						featureKVStoreBucketKey)
				}

				// The feature name should exist, as per the
				// verification above.
				featureBucket := ftBkt.Bucket(ftName)
				if featureBucket == nil {
					return fmt.Errorf("feature bucket "+
						"%s not found", ftName)
				}

				featurePairs, err := collectKVPairs(
					featureBucket, true, perm, rule,
					fn.Some(groupAlias),
					fn.Some(string(ftName)),
				)
				if err != nil {
					return fmt.Errorf("collecting "+
						"feature kv pairs failed: %w",
						err)
				}

				params = append(params, featurePairs...)

				return nil
			})
		})
		if err != nil {
			return nil, fmt.Errorf("collecting session kv pairs "+
				"failed: %w", err)
		}
	}

	return params, nil
}

// collectKVPairs collects all key-value pairs from the given bucket, and
// returns them as a slice of kvEntry structs. If the errorOnBuckets parameter
// is set to true, then the function will return an error if the bucket
// contains any sub-buckets. Note that when the errorOnBuckets parameter is
// set to false, the function will not collect any key-value pairs from the
// sub-buckets, and will just ignore them.
func collectKVPairs(bkt *bbolt.Bucket, errorOnBuckets, perm bool,
	ruleName string, groupAlias fn.Option[[]byte],
	featureName fn.Option[string]) ([]*kvEntry, error) {

	var params []*kvEntry

	return params, bkt.ForEach(func(key, value []byte) error {
		// If the value is nil, then this is a bucket, which we
		// don't want to process here, as we only want to collect
		// the key-value pairs, not the buckets. If we should
		// error on buckets, then we return an error here.
		if value == nil {
			if errorOnBuckets {
				return fmt.Errorf("unexpected bucket %s found "+
					"in when collecting kv pairs", key)
			}

			return nil
		}

		params = append(params, &kvEntry{
			perm:        perm,
			ruleName:    ruleName,
			key:         string(key),
			featureName: featureName,
			groupAlias:  groupAlias,
			value:       value,
		})

		return nil
	})
}

// insertPair inserts a single key-value pair into the SQL database.
func insertPair(ctx context.Context, tx SQLQueries,
	entry *kvEntry) (*sqlKvEntry, error) {

	ruleID, err := tx.GetOrInsertRuleID(ctx, entry.ruleName)
	if err != nil {
		return nil, err
	}

	p := sqlc.InsertKVStoreRecordParams{
		Perm:     entry.perm,
		RuleID:   ruleID,
		EntryKey: entry.key,
		Value:    entry.value,
	}

	entry.groupAlias.WhenSome(func(alias []byte) {
		var groupID int64
		groupID, err = tx.GetSessionIDByAlias(ctx, alias)
		if err != nil {
			err = fmt.Errorf("getting group id by alias %x "+
				"failed: %w", alias, err)
			return
		}

		p.GroupID = sqldb.SQLInt64(groupID)
	})
	if err != nil {
		return nil, err
	}

	entry.featureName.WhenSome(func(feature string) {
		var featureID int64
		featureID, err = tx.GetOrInsertFeatureID(ctx, feature)
		if err != nil {
			err = fmt.Errorf("getting/inserting feature id for %s "+
				"failed: %w", feature, err)
			return
		}

		p.FeatureID = sqldb.SQLInt64(featureID)
	})
	if err != nil {
		return nil, err
	}

	err = tx.InsertKVStoreRecord(ctx, p)
	if err != nil {
		return nil, err
	}

	return &sqlKvEntry{
		kvEntry:   entry,
		ruleID:    p.RuleID,
		groupID:   p.GroupID,
		featureID: p.FeatureID,
	}, nil
}

// getSQLValue retrieves the key value for the given kvEntry from the SQL
// database.
func getSQLValue(ctx context.Context, tx SQLQueries,
	entry *sqlKvEntry) ([]byte, error) {

	switch {
	case entry.featureID.Valid && entry.groupID.Valid:
		return tx.GetFeatureKVStoreRecord(
			ctx, sqlc.GetFeatureKVStoreRecordParams{
				Perm:      entry.perm,
				RuleID:    entry.ruleID,
				GroupID:   entry.groupID,
				FeatureID: entry.featureID,
				Key:       entry.key,
			},
		)
	case entry.groupID.Valid:
		return tx.GetGroupKVStoreRecord(
			ctx, sqlc.GetGroupKVStoreRecordParams{
				Perm:    entry.perm,
				RuleID:  entry.ruleID,
				GroupID: entry.groupID,
				Key:     entry.key,
			},
		)
	case !entry.featureID.Valid && !entry.groupID.Valid:
		return tx.GetGlobalKVStoreRecord(
			ctx, sqlc.GetGlobalKVStoreRecordParams{
				Perm:   entry.perm,
				RuleID: entry.ruleID,
				Key:    entry.key,
			},
		)
	default:
		return nil, fmt.Errorf("invalid combination of feature and "+
			"session ID: featureID valid: %v, groupID valid: %v",
			entry.featureID.Valid, entry.groupID.Valid)
	}
}

// verifyBktKeys checks that the given bucket only contains buckets with the
// passed keys, and optionally also key-value pairs. If the errorOnKeyValues
// parameter is set to true, the function will error if it finds key-value pairs
// in the bucket.
func verifyBktKeys(bkt *bbolt.Bucket, errorOnKeyValues bool,
	keys ...[]byte) error {

	return bkt.ForEach(func(key, v []byte) error {
		if v != nil {
			// If we allow key-values, then we can just continue
			// to the next key. Else we need to error out, as we
			// only expect buckets under the passed bucket.
			if errorOnKeyValues {
				return fmt.Errorf("unexpected key-value pair "+
					"found: key=%s, value=%x", key, v)
			}

			return nil
		}

		for _, expectedKey := range keys {
			if bytes.Equal(key, expectedKey) {
				// If this is an expected key, we can continue
				// to the next key.
				return nil
			}
		}

		return fmt.Errorf("unexpected key found: %s", key)
	})
}

// migratePrivacyMapperDBToSQL runs the migration of the privacy mapper store
// from the KV database to the SQL database. The function also asserts that the
// migrated values match the original values in the privacy mapper store.
func migratePrivacyMapperDBToSQL(ctx context.Context, kvStore *bbolt.DB,
	sqlTx SQLQueries) error {

	log.Infof("Starting migration of the privacy mapper store to SQL")

	// 1) Collect all privacy pairs from the KV store.
	privPairs, err := collectPrivacyPairs(ctx, kvStore, sqlTx)
	if err != nil {
		return fmt.Errorf("error migrating privacy mapper store: %w",
			err)
	}

	// 2) Insert all collected privacy pairs into the SQL database.
	err = insertPrivacyPairs(ctx, sqlTx, privPairs)
	if err != nil {
		return fmt.Errorf("insertion of privacy pairs failed: %w", err)
	}

	// 3) Validate that all inserted privacy pairs match the original values
	// in the KV store. Note that this is done after all values have been
	// inserted, to ensure that the migration doesn't overwrite any values
	// after they were inserted.
	err = validatePrivacyPairsMigration(ctx, sqlTx, privPairs)
	if err != nil {
		return fmt.Errorf("migration validation of privacy pairs "+
			"failed: %w", err)
	}

	log.Infof("Migration of the privacy mapper stores to SQL completed. "+
		"Total number of rows migrated: %d", len(privPairs))

	return nil
}

// collectPrivacyPairs collects all privacy pairs from the KV store.
func collectPrivacyPairs(ctx context.Context, kvStore *bbolt.DB,
	sqlTx SQLQueries) (privacyPairs, error) {

	groupPairs := make(privacyPairs)

	return groupPairs, kvStore.View(func(kvTx *bbolt.Tx) error {
		bkt := kvTx.Bucket(privacyBucketKey)
		if bkt == nil {
			// If we haven't generated any privacy bucket yet,
			// we can skip the migration, as there are no privacy
			// pairs to migrate.
			return nil
		}

		return bkt.ForEach(func(groupId, v []byte) error {
			if v != nil {
				return fmt.Errorf("expected only buckets "+
					"under %s bkt, but found value %s",
					privacyBucketKey, v)
			}

			gBkt := bkt.Bucket(groupId)
			if gBkt == nil {
				return fmt.Errorf("group bkt for group id "+
					"%s not found", groupId)
			}

			groupSqlId, err := sqlTx.GetSessionIDByAlias(
				ctx, groupId,
			)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("session with group id %x "+
					"not found in sql db", groupId)
			} else if err != nil {
				return err
			}

			groupRealToPseudoPairs, err := collectGroupPairs(gBkt)
			if err != nil {
				return fmt.Errorf("processing group bkt "+
					"for group id %s (sqlID %d) failed: %w",
					groupId, groupSqlId, err)
			}

			groupPairs[groupSqlId] = groupRealToPseudoPairs

			return nil
		})
	})
}

// collectGroupPairs collects all privacy pairs for a specific session group,
// i.e. the group buckets under the privacy mapper bucket in the KV store.
// The function returns them as a map, where the key is the real value, and
// the value for the key is the pseudo values.
// It also checks that the pairs are consistent, i.e. that for each real value
// there is a corresponding pseudo value, and vice versa. If the pairs are
// inconsistent, it returns an error indicating the mismatch.
func collectGroupPairs(bkt *bbolt.Bucket) (map[string]string, error) {
	var (
		realToPseudoRes map[string]string
		pseudoToRealRes map[string]string
		err             error
	)

	if realBkt := bkt.Bucket(realToPseudoKey); realBkt != nil {
		realToPseudoRes, err = collectPairs(realBkt)
		if err != nil {
			return nil, fmt.Errorf("fetching real to pseudo pairs "+
				"failed: %w", err)
		}
	} else {
		return nil, fmt.Errorf("%s bucket not found", realToPseudoKey)
	}

	if pseudoBkt := bkt.Bucket(pseudoToRealKey); pseudoBkt != nil {
		pseudoToRealRes, err = collectPairs(pseudoBkt)
		if err != nil {
			return nil, fmt.Errorf("fetching pseudo to real pairs "+
				"failed: %w", err)
		}
	} else {
		return nil, fmt.Errorf("%s bucket not found", pseudoToRealKey)
	}

	if len(realToPseudoRes) != len(pseudoToRealRes) {
		return nil, fmt.Errorf("missmatch between nubmer of pairs in "+
			"%s bucket (pairs found: %d) and %s bucket (pairs "+
			"found: %d)", realToPseudoKey, len(realToPseudoRes),
			pseudoToRealKey, len(pseudoToRealRes))
	}

	for realVal, pseudoVal := range realToPseudoRes {
		if rv, ok := pseudoToRealRes[pseudoVal]; !ok || rv != realVal {
			return nil, fmt.Errorf("the real value %s found in "+
				"the %s bucket doesn't match the value %s "+
				"found in the %s bucket",
				realVal, realToPseudoKey, rv, pseudoToRealKey)
		}
	}

	return realToPseudoRes, nil
}

// collectPairs collects all privacy pairs from a specific realToPseudoKey or
// pseudoToRealKey bucket in the KV store. It returns a map where the key is
// the real value or pseudo value, and the value is the corresponding pseudo
// value or real value, respectively (depending on if the realToPseudo or
// pseudoToReal bucket is passed to the function).
func collectPairs(pairsBucket *bbolt.Bucket) (map[string]string, error) {
	pairsRes := make(map[string]string)

	return pairsRes, pairsBucket.ForEach(func(k, v []byte) error {
		if v == nil {
			return fmt.Errorf("expected only key-values under "+
				"pairs bucket, but found bucket %s", k)
		}

		if len(v) == 0 {
			return fmt.Errorf("empty value stored for privacy "+
				"pairs key %s", k)
		}

		pairsRes[string(k)] = string(v)

		return nil
	})
}

// insertPrivacyPairs inserts the collected privacy pairs into the SQL database.
func insertPrivacyPairs(ctx context.Context, sqlTx SQLQueries,
	pairs privacyPairs) error {

	for groupId, groupPairs := range pairs {
		err := insertGroupPairs(ctx, sqlTx, groupId, groupPairs)
		if err != nil {
			return fmt.Errorf("inserting group pairs for group "+
				"id %d failed: %w", groupId, err)
		}
	}

	return nil
}

// insertGroupPairs inserts the privacy pairs for a specific group into
// the SQL database. It checks for duplicates before inserting, and returns
// an error if a duplicate pair is found. The function takes a map of real
// to pseudo values, where the key is the real value and the value is the
// corresponding pseudo value.
func insertGroupPairs(ctx context.Context, sqlTx SQLQueries, groupID int64,
	pairs map[string]string) error {

	for realVal, pseudoVal := range pairs {
		err := sqlTx.InsertPrivacyPair(
			ctx, sqlc.InsertPrivacyPairParams{
				GroupID:   groupID,
				RealVal:   realVal,
				PseudoVal: pseudoVal,
			},
		)
		if err != nil {
			return fmt.Errorf("inserting privacy pair %s:%s "+
				"failed: %w", realVal, pseudoVal, err)
		}
	}

	return nil
}

// validatePrivacyPairsMigration validates that the migrated privacy pairs
// match the original values in the KV store.
func validatePrivacyPairsMigration(ctx context.Context, sqlTx SQLQueries,
	pairs privacyPairs) error {

	for groupId, groupPairs := range pairs {
		err := validateGroupPairsMigration(
			ctx, sqlTx, groupId, groupPairs,
		)
		if err != nil {
			return fmt.Errorf("migration validation of privacy "+
				"pairs for group %d failed: %w", groupId, err)
		}
	}

	return nil
}

// validateGroupPairsMigration validates that the migrated privacy pairs for
// a specific group match the original values in the KV store. It checks that
// for each real value, the pseudo value in the SQL database matches the
// original pseudo value, and vice versa. If any mismatch is found, it returns
// an error indicating the mismatch.
func validateGroupPairsMigration(ctx context.Context, sqlTx SQLQueries,
	groupID int64, pairs map[string]string) error {

	for realVal, pseudoVal := range pairs {
		resPseudoVal, err := sqlTx.GetPseudoForReal(
			ctx, sqlc.GetPseudoForRealParams{
				GroupID: groupID,
				RealVal: realVal,
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("migrated privacy pair %s:%s not "+
				"found for real value", realVal, pseudoVal)
		}
		if err != nil {
			return err
		}

		if resPseudoVal != pseudoVal {
			return fmt.Errorf("pseudo value in db %s, does not "+
				"match original value %s, for real value %s",
				resPseudoVal, pseudoVal, realVal)
		}

		resRealVal, err := sqlTx.GetRealForPseudo(
			ctx, sqlc.GetRealForPseudoParams{
				GroupID:   groupID,
				PseudoVal: pseudoVal,
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("migrated privacy pair %s:%s not "+
				"found for pseudo value", realVal, pseudoVal)
		}
		if err != nil {
			return err
		}

		if resRealVal != realVal {
			return fmt.Errorf("real value in db %s, does not "+
				"match original value %s, for pseudo value %s",
				resRealVal, realVal, pseudoVal)
		}
	}

	return nil
}

func migrateActionsToSQL(ctx context.Context, kvStore *bbolt.DB,
	sqlTx SQLQueries, sessionDB session.SQLQueries,
	accountsDB accounts.SQLQueries, macRootKeyIDs [][]byte) error {

	log.Infof("Starting migration of the actions store to SQL")

	accts, err := accountsDB.ListAllAccounts(ctx)
	if err != nil {
		return fmt.Errorf("listing accounts failed: %w", err)
	}

	acctsMap, err := mapAccounts(accts)
	if err != nil {
		return fmt.Errorf("mapping accounts failed: %w", err)
	}

	sessions, err := sessionDB.ListSessions(ctx)
	if err != nil {
		return fmt.Errorf("listing sessions failed: %w", err)
	}

	sessionsMap, err := mapSessions(sessions)
	if err != nil {
		return fmt.Errorf("mapping sessions failed: %w", err)
	}

	macMap, err := mapMacIds(macRootKeyIDs)
	if err != nil {
		return fmt.Errorf("mapping macaroon root key IDs failed: %w",
			err)
	}

	migratedActions := 0

	err = kvStore.View(func(tx *bbolt.Tx) error {
		actionsBucket := tx.Bucket(actionsBucketKey)
		if actionsBucket == nil {
			return fmt.Errorf("actions bucket not found")
		}

		sessionsBucket := actionsBucket.Bucket(actionsKey)
		if sessionsBucket == nil {
			return fmt.Errorf("actions->sessions bucket not found")
		}

		// Iterate over session ID buckets (i.e. what we should name
		// macaroon IDs)
		return sessionsBucket.ForEach(func(macID []byte, v []byte) error {
			if v != nil {
				return fmt.Errorf("expected only sub-buckets " +
					"in sessions bucket")
			}

			sessBucket := sessionsBucket.Bucket(macID)
			if sessBucket == nil {
				return fmt.Errorf("session bucket for %x not "+
					"found", macID)
			}

			var macIDArr [4]byte
			copy(macIDArr[:], macID)

			macRootKeyID, ok := macMap[macIDArr]
			if !ok {
				// If we don't have a mapping for this macaroon
				// ID, this could mean that the user has deleted
				// the lnd macaroon db, but not the litd
				// firewalldb.
				// As there is no way to recover the full
				// macaroonRootKeyID at this point, we backfill
				// the rest of the bytes with zeroes.
				log.Warnf("No macaroon root key ID found for "+
					"macaroon ID %x, using zeroes for "+
					"the rest of the bytes", macID)

				macRootKeyID = make([]byte, 8)
				copy(macRootKeyID, macIDArr[:])
			}

			// Iterate over actions inside each session
			return sessBucket.ForEach(func(actionID,
				actionBytes []byte) error {

				if actionBytes == nil {
					return fmt.Errorf("unexpected nested "+
						"bucket under session %x",
						macID)
				}

				sessionID, err := session.IDFromBytes(macID)
				if err != nil {
					// Should be unreachable, as the macID
					// should always be 4 bytes long.
					return fmt.Errorf("invalid session ID "+
						"format %x: %v", macID, err)
				}

				action, err := DeserializeAction(
					bytes.NewReader(actionBytes), sessionID,
				)
				if err != nil {
					return fmt.Errorf("unable to "+
						"deserialize action in "+
						"session %x: %w", macID, err)
				}

				err = migrateActionToSQL(
					ctx, sqlTx, acctsMap, sessionsMap,
					action, macRootKeyID,
				)
				if err != nil {
					return fmt.Errorf("migrating action "+
						"to SQL failed: %w", err)
				}

				migratedActions++

				return nil
			})
		})
	})
	if err != nil {
		return fmt.Errorf("migration of the actions store to SQL "+
			"failed: %w", err)
	}

	log.Infof("Migration %d actions to SQL completed", migratedActions)

	return nil
}

func migrateActionToSQL(ctx context.Context, sqlTx SQLQueries,
	acctsMap map[[4]byte][]sqlc.Account, sessMap map[[4]byte][]sqlc.Session,
	action *Action, macRootKeyID []byte) error {

	macId, err := action.MacaroonIdentifier.UnwrapOrErr(
		fmt.Errorf("no macaroon identifier set for action during" +
			"migration of action to SQL"),
	)
	if err != nil {
		// Should be unreachable, as the DeserializeAction function in
		// actions_kvdb only has a fn.Some path for the
		// MacaroonIdentifier, whenever the function doesn't error.
		return err
	}

	actAccounts, hasAccounts := acctsMap[macId]
	actSessions, hasSessions := sessMap[macId]

	var insertParams sqlc.InsertActionParams

	switch {
	case hasAccounts && hasSessions:
		insertParams = paramsFromBothSessionsAndAccounts(
			action, actAccounts, actSessions, macRootKeyID,
		)
	case hasAccounts:
		insertParams = paramsFromAccounts(
			action, actAccounts, macRootKeyID)
	case hasSessions:
		insertParams = paramsFromSessions(
			action, actSessions, macRootKeyID,
		)
	default:
		insertParams = paramsFromAction(action, macRootKeyID)
	}

	_, err = sqlTx.InsertAction(ctx, insertParams)

	// TODO: Add validation

	return err
}

func paramsFromBothSessionsAndAccounts(action *Action, actAccts []sqlc.Account,
	sess []sqlc.Session, macRootKeyID []byte) sqlc.InsertActionParams {

	acctOpt := getMatchingAccountForAction(action, actAccts)
	sessOpt := getMatchingSessionForAction(action, sess)

	switch {
	case acctOpt.IsSome() && sessOpt.IsSome():
		// If we find both a potential linked account and session, we
		// prio linking the session to the action.
		return paramsFromSessions(action, sess, macRootKeyID)
	case acctOpt.IsSome():
		return paramsFromAccounts(action, actAccts, macRootKeyID)
	case sessOpt.IsSome():
		return paramsFromSessions(action, sess, macRootKeyID)
	default:
		// If no potential linked account or session were found after
		// filtering, we won't link the action to any of them.
		return paramsFromAction(action, macRootKeyID)
	}
}

func paramsFromSessions(action *Action,
	sessAccts []sqlc.Session, macRootKeyID []byte) sqlc.InsertActionParams {

	sessOpt := getMatchingSessionForAction(action, sessAccts)

	params := paramsFromAction(action, macRootKeyID)

	sessOpt.WhenSome(func(sess sqlc.Session) {
		params.SessionID = sql.NullInt64{Int64: sess.ID, Valid: true}
	})

	return params
}

func paramsFromAccounts(action *Action,
	actAccts []sqlc.Account, macRootKeyID []byte) sqlc.InsertActionParams {

	acctOpt := getMatchingAccountForAction(action, actAccts)

	params := paramsFromAction(action, macRootKeyID)

	acctOpt.WhenSome(func(acct sqlc.Account) {
		params.AccountID = sql.NullInt64{Int64: acct.ID, Valid: true}
	})

	return params
}

func paramsFromAction(action *Action,
	macRootKeyID []byte) sqlc.InsertActionParams {

	return sqlc.InsertActionParams{
		MacaroonIdentifier: macRootKeyID,
		ActorName: sql.NullString{
			String: action.ActorName,
			Valid:  len(action.ActorName) > 0,
		},
		FeatureName: sql.NullString{
			String: action.FeatureName,
			Valid:  len(action.FeatureName) > 0,
		},
		ActionTrigger: sql.NullString{
			String: action.Trigger,
			Valid:  len(action.Trigger) > 0,
		},
		Intent: sql.NullString{
			String: action.Intent,
			Valid:  len(action.Intent) > 0,
		},
		StructuredJsonData: []byte(action.StructuredJsonData),
		RpcMethod:          action.RPCMethod,
		RpcParamsJson:      action.RPCParamsJson,
		CreatedAt:          action.AttemptedAt,
		ActionState:        int16(action.State),
		ErrorReason: sql.NullString{
			String: action.ErrorReason,
			Valid:  len(action.ErrorReason) > 0,
		},
	}
}

func getMatchingSessionForAction(action *Action,
	sessAccts []sqlc.Session) fn.Option[sqlc.Session] {

	attempted := action.AttemptedAt

	// 1) Do some initial filtering of the sessions
	// Note that after session linking was added, we shouldn't have multiple
	// sessions which have colliding ID's. But as the action could have been
	// triggered on a litd version which didn't have that collision
	// detection logic, we cannot assume that the sql migration won't need
	// to handle such cases.
	filtered := make([]sqlc.Session, 0, len(sessAccts))
	for _, s := range sessAccts {
		// Exclude if revoked before the attempt time
		if s.RevokedAt.Valid && s.RevokedAt.Time.Before(attempted) {
			continue
		}
		// Exclude if created after the attempt time
		if s.CreatedAt.After(attempted) {
			continue
		}
		// Exclude if expired before the attempt time
		if s.Expiry.Before(attempted) {
			continue
		}
		filtered = append(filtered, s)
	}

	// 2) If no sessions remain after filtering, no potential linked session
	// for the action was found.
	if len(filtered) == 0 {
		return fn.None[sqlc.Session]()
	}

	// 3) If multiple session remain after filtering, we pick the one with
	// the latest CreatedAt time.
	if len(filtered) > 1 {
		sort.Slice(filtered, func(i, j int) bool {
			// Sort descending by CreatedAt (latest first)
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		})
	}

	// 4) Return the first session of the filtered list, which has been
	// sorted if multiple sessions remain.
	return fn.Some(filtered[0])
}

func getMatchingAccountForAction(action *Action,
	actAccts []sqlc.Account) fn.Option[sqlc.Account] {

	if action.ActorName != "" {
		return fn.None[sqlc.Account]()
	}

	attempted := action.AttemptedAt

	// 1) Do some initial filtering of the accounts
	filtered := make([]sqlc.Account, 0, len(actAccts))
	for _, a := range actAccts {
		// Exclude if expired before the attempt time
		if a.Expiration.Before(attempted) && !a.Expiration.IsZero() {
			continue
		}

		// TODO:
		/*if action.RPCMethod == "/lnrpc.Lightning/AddInvoice" {
			if len(action.invoices) == 0 {
				continue
			}

		}

		if action.RPCMethod == "/routerrpc.Router/SendPaymentV2" {
			if len(action.payments) == 0 {
				continue
			}

		}
		*/

		filtered = append(filtered, a)
	}

	// 2) If no accounts remain after filtering, no potential linked account
	// for the action was found.
	if len(filtered) == 0 {
		return fn.None[sqlc.Account]()
	}

	// 3) If multiple session remain after filtering, we pick the one with
	// the latest expiration, but  where non expiring accounts are picked
	// first.
	if len(filtered) > 1 {
		sort.Slice(filtered, func(i, j int) bool {
			// TODO: we can also grab all of the account's payments
			// and invoices and determine if any of them are
			// directly linkable to the action. If we find a match,
			// we can be confident that this action belongs to that
			// account.
			// This will require that we pass the basic lnd client
			// to the migration function, and will not work for all
			// actions related to the account, so may add more
			// complexity than it's worth.

			zeroI := filtered[i].Expiration.IsZero()
			zeroJ := filtered[j].Expiration.IsZero()

			// If one is zero and the other is not, zero comes first
			if zeroI && !zeroJ {
				return true
			}
			if zeroJ && !zeroI {
				return false
			}

			// Both are zero or both are non-zero
			// If both are non-zero, latest expiration first
			return filtered[i].Expiration.After(filtered[j].Expiration)
		})
	}

	// 4) Return the first account of the filtered list, which has been
	// sorted if multiple accounts remain.
	return fn.Some(filtered[0])
}

func mapMacIds(macRootKeyIDs [][]byte) (map[[4]byte][]byte, error) {
	// Start by converting the macRootKeyIDs to a map that let's us map the
	// macaroon the 4 byte identifiers to the full uint64 RootKeyID.
	macMap := make(map[[4]byte][]byte)

	for _, id := range macRootKeyIDs {
		if len(id) < 4 {
			return nil, fmt.Errorf("expected rootKeyID to be at "+
				"least 4 bytes long, got %d bytes", len(id))
		}

		var rootKeyShortID [4]byte
		copy(rootKeyShortID[:], id[len(id)-4:]) // last 4 bytes

		// NOTE: If we already have an entry for this rootKeyShortID,
		// we overwrite it with the new RootKeyID, as we can't determine
		// which one is the correct one.
		macMap[rootKeyShortID] = id
	}

	return macMap, nil
}

func mapAccounts(accts []sqlc.Account) (map[[4]byte][]sqlc.Account, error) {
	acctMap := make(map[[4]byte][]sqlc.Account)

	for _, acct := range accts {
		aliasBytes := make([]byte, 8)

		// Convert the int64 account Alias to bytes (big-endian)
		binary.BigEndian.PutUint64(aliasBytes, uint64(acct.Alias))

		var acctPrefix [4]byte
		copy(acctPrefix[:], aliasBytes[:4])

		if acctList, ok := acctMap[acctPrefix]; ok {
			acctMap[acctPrefix] = append(acctList, acct)
		} else {
			acctMap[acctPrefix] = []sqlc.Account{acct}
		}
	}

	return acctMap, nil
}

func mapSessions(sessions []sqlc.Session) (map[[4]byte][]sqlc.Session, error) {
	sessMap := make(map[[4]byte][]sqlc.Session)

	for _, sess := range sessions {
		if len(sess.Alias) != 4 {
			return nil, fmt.Errorf("session alias must be 4 "+""+
				"bytes, got %d bytes", len(sess.Alias))
		}

		var sessAlias [4]byte
		copy(sessAlias[:], sess.Alias[:4])

		if acctList, ok := sessMap[sessAlias]; ok {
			sessMap[sessAlias] = append(acctList, sess)
		} else {
			sessMap[sessAlias] = []sqlc.Session{sess}
		}
	}

	return sessMap, nil
}
