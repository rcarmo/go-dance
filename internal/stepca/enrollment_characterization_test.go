package stepca

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/smallstep/certificates/acme"
	acmenosql "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

// These tests characterise the pinned upstream backend for issue #2. They do
// not implement the proposed API or change existing CA state.
func enrollmentTestDB(t *testing.T, driver string) (nosql.DB, *acmenosql.DB) {
	t.Helper()
	raw, err := nosql.New(driver, filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Error(err)
		}
	})
	db, err := acmenosql.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, db
}

func TestEnrollmentCharacterizationReferenceConflictLeavesCreatedKey(t *testing.T) {
	for _, driver := range []string{"badger", "badgerv2"} {
		t.Run(driver, func(t *testing.T) {
			_, db := enrollmentTestDB(t, driver)
			ctx := context.Background()
			first, err := db.CreateExternalAccountKey(ctx, "provisioner", "same-reference")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateExternalAccountKey(ctx, "provisioner", "same-reference"); err == nil {
				t.Fatal("expected a conflicting reference to fail")
			}
			keys, _, err := db.GetExternalAccountKeys(ctx, "provisioner", "", 100)
			if err != nil {
				t.Fatal(err)
			}
			// Upstream writes the key and provisioner index before its unique reference
			// index. A failed creation is therefore not evidence that no key was minted.
			if len(keys) != 2 {
				t.Fatalf("pinned backend left %d keys, expected 2", len(keys))
			}
			if keys[0].ID == keys[1].ID {
				t.Fatal("expected distinct keys")
			}
			byReference, err := db.GetExternalAccountKeyByReference(ctx, "provisioner", "same-reference")
			if err != nil {
				t.Fatal(err)
			}
			if byReference.ID != first.ID {
				t.Fatal("reference no longer resolves to original key")
			}

		})
	}
}

func TestEnrollmentCharacterizationBindingClearsSecretButDeletionAllowsBoundKey(t *testing.T) {
	for _, driver := range []string{"badger", "badgerv2"} {
		t.Run(driver, func(t *testing.T) {
			_, db := enrollmentTestDB(t, driver)
			ctx := context.Background()
			key, err := db.CreateExternalAccountKey(ctx, "provisioner", "reference")
			if err != nil {
				t.Fatal(err)
			}
			if err := key.BindTo(&acme.Account{ID: "test-account"}); err != nil {
				t.Fatal(err)
			}
			if err := db.UpdateExternalAccountKey(ctx, "provisioner", key); err != nil {
				t.Fatal(err)
			}
			bound, err := db.GetExternalAccountKey(ctx, "provisioner", key.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !bound.AlreadyBound() || len(bound.HmacKey) != 0 {
				t.Fatal("bound key must have no HMAC")
			}
			if err := bound.BindTo(&acme.Account{ID: "other-account"}); err == nil {
				t.Fatal("bound key unexpectedly reusable")
			}
			// Dance's proposed unused-key invalidation cannot simply delegate deletion:
			// the upstream delete operation itself permits deleting this bound key.
			if err := db.DeleteExternalAccountKey(ctx, "provisioner", key.ID); err != nil {
				t.Fatal(err)
			}

		})
	}
}

func TestEnrollmentCharacterizationBadgerTransactionGuardLimitations(t *testing.T) {
	for _, driver := range []string{"badger", "badgerv2"} {
		t.Run(driver, func(t *testing.T) {
			raw, _ := enrollmentTestDB(t, driver)
			bucket := []byte("dance_enrollment_probe")
			if err := raw.CreateTable(bucket); err != nil {
				t.Fatal(err)
			}
			if err := raw.Set(bucket, []byte("guard"), []byte("actual")); err != nil {
				t.Fatal(err)
			}
			tx := new(database.Tx)
			tx.Set(bucket, []byte("mutation"), []byte("must-not-commit"))
			tx.Cmp(bucket, []byte("guard"), []byte("wrong"))
			if err := raw.Update(tx); !nosql.IsErrOpNotSupported(err) {
				t.Fatal("expected pinned Badger backend to reject CmpOrRollback")
			}
			if _, err := raw.Get(bucket, []byte("mutation")); !nosql.IsErrNotFound(err) {
				t.Fatal("failed transaction did not roll back mutation")
			}
			tx = new(database.Tx)
			tx.Cas(bucket, []byte("guard"), []byte("replacement"))
			tx.Operations[0].CmpValue = []byte("wrong")
			tx.Set(bucket, []byte("mutation"), []byte("committed"))
			if err := raw.Update(tx); err != nil {
				t.Fatal(err)
			}
			if tx.Operations[0].Swapped {
				t.Fatal("unexpected CAS success with mismatched comparison")
			}
			// A failed CAS is a result, not a transaction abort. Checking Swapped
			// after Update returns is too late to prevent other writes committing.
			value, err := raw.Get(bucket, []byte("mutation"))
			if err != nil || string(value) != "committed" {
				t.Fatal("expected other writes to commit despite the failed CAS")
			}

		})
	}
}
