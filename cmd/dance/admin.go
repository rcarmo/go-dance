// The admin subcommand manages machine grants using the local operator's filesystem
// authority over Dance's application database. It never opens CA keys/state.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/rcarmo/dance/internal/store"
)

func runAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stdout, "Usage: dance admin grant|revoke [options]\nUse dance admin grant -h or dance admin revoke -h for options.")
		return nil
	}
	action := args[0]
	if action != "grant" && action != "revoke" {
		return fmt.Errorf("expected dance admin grant|revoke")
	}
	f := flag.NewFlagSet("dance admin "+action, flag.ContinueOnError)
	dbPath := f.String("db", "", "Dance SQLite database (required)")
	target := f.String("target", "", "target inventory label")
	provs := f.String("provisioners", "", "comma-separated canonical provisioner IDs")
	ops := f.String("operations", "provisioners:read,eab:create,eab:read-own", "comma-separated operations")
	prefix := f.String("reference-prefix", "", "permitted reference prefix")
	ttl := f.Duration("ttl", 24*time.Hour, "credential lifetime")
	out := f.String("out", "", "new private credential file, required for grant")
	id := f.String("id", "", "credential ID to revoke")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if *dbPath == "" || f.NArg() != 0 {
		return fmt.Errorf("specify -db and no positional arguments")
	}
	// Do not silently create a second, empty app database at a typoed path.
	if info, err := os.Stat(*dbPath); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("existing Dance database required")
	}
	st, err := store.NewSQLite(*dbPath)
	if err != nil {
		return fmt.Errorf("database unavailable")
	}
	defer st.Close()
	if err := st.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("schema unavailable")
	}
	if action == "revoke" {
		if *id == "" {
			return fmt.Errorf("-id required")
		}
		return st.RevokeMachine(ctx, *id)
	}
	if *out == "" || *target == "" || *provs == "" || *ttl <= 0 {
		return fmt.Errorf("grant requires -out, -target, -provisioners and positive -ttl")
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot reserve new private output file")
	}
	success := false
	defer func() {
		file.Close()
		if !success {
			os.Remove(*out)
		}
	}()
	token, err := st.MintMachine(ctx, enrollment.Principal{Target: *target, Provisioners: strings.Split(*provs, ","), Operations: strings.Split(*ops, ","), ReferencePrefix: *prefix, ExpiresAt: time.Now().UTC().Add(*ttl)})
	if err != nil {
		return fmt.Errorf("grant failed")
	}
	if _, err = file.WriteString(token + "\n"); err == nil {
		err = file.Sync()
	}
	if err != nil {
		publicID := strings.Split(strings.TrimPrefix(token, "dance_"), ".")[0]
		if revokeErr := st.RevokeMachine(ctx, publicID); revokeErr != nil {
			return fmt.Errorf("credential delivery uncertain; operator must reconcile/revoke credential %s", publicID)
		}
		return fmt.Errorf("credential delivery failed; grant revoked")
	}
	success = true
	publicID := strings.Split(strings.TrimPrefix(token, "dance_"), ".")[0]
	fmt.Printf("Machine credential %s written to private output file; deliver it to the authorised HTTPS client through a trusted channel.\n", publicID)
	return nil
}
