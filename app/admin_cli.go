package app

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// The out-of-band reset is a break-glass path, so the audit entry has to say so
// rather than look like an ordinary administrative reset. Anyone who can run it
// already has a shell in the container; what the record is for is telling the
// investigator afterwards that the change came from there and not from a
// console session.
const (
	cliActorType = "cli"
	cliActorName = "admin cli (out-of-band)"
	cliActorIP   = "127.0.0.1"
)

// runResetPassword implements `mxid-server admin reset-password`.
//
// Why a subcommand on the server binary rather than a separate tool: the image
// already ships this binary, so the command exists wherever the product is
// deployed — no extra build target, no second thing to copy into an air-gapped
// bundle — and `kubectl exec <pod> -- ./mxid admin reset-password` needs nothing
// staged in advance. That matters because the situation it exists for is
// "nobody can sign in", which is exactly when there is no time to build tools.
//
// It goes through user.Service.ResetPassword rather than writing the row
// itself, so the password policy, the reuse history, the single transaction
// across hash/must-change/history, and the session revocation that follows
// UserPasswordChanged all apply. A hand-written UPDATE — the only recovery that
// existed before this — skipped every one of them, and left no audit trail.
func runResetPassword(a *bootstrap.App, args []string) error {
	fs := flag.NewFlagSet("admin reset-password", flag.ContinueOnError)
	username := fs.String("username", "", "account to reset (required)")
	fromStdin := fs.Bool("stdin", false, "read the new password from stdin instead of prompting")
	generate := fs.Bool("generate", false, "generate a strong password and print it")
	unlock := fs.Bool("unlock", false, "also return a locked or disabled account to active")
	// Deliberately no -password flag: it would land in shell history and in the
	// process list, which is the exposure this command exists to avoid.
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*username) == "" {
		fs.Usage()
		return errors.New("-username is required")
	}
	if *generate && *fromStdin {
		return errors.New("-generate and -stdin are mutually exclusive")
	}

	tenantID := a.Config.Tenant.DefaultID
	// Scope the context: the user repository is tenant-scoped, and a CLI has no
	// request to inherit a scope from.
	ctx := tenantscope.WithTenant(context.Background(), tenantID)
	ctx = auditctx.With(ctx, auditctx.Actor{
		ActorType: cliActorType,
		ActorName: cliActorName,
		TenantID:  tenantID,
		IP:        cliActorIP,
	})

	userModule := user.Register(a)
	svc := userModule.Service

	// Same runtime policy the console enforces, not the YAML fallback: a
	// recovery path that quietly accepts weaker passwords than the product
	// demands everywhere else is a backdoor around the policy.
	settingRepo := setting.NewRepositoryWithIDGen(a.DB, a.IDGen)
	settingService := setting.NewService(settingRepo, a.MasterKey)
	svc.SetPasswordPolicyProvider(func(ctx context.Context, tid int64) user.PasswordPolicy {
		ctx = tenantscope.WithTenant(ctx, tid)
		pol, err := settingService.SecurityPolicy(ctx, tid)
		if err != nil {
			pol = setting.DefaultSecurityPolicy()
		}
		return user.PasswordPolicy{
			MinLength:        pol.Password.MinLength,
			RequireUppercase: pol.Password.RequireUppercase,
			RequireLowercase: pol.Password.RequireLowercase,
			RequireNumber:    pol.Password.RequireNumber,
			RequireSpecial:   pol.Password.RequireSpecial,
			HistoryCount:     pol.Password.HistoryCount,
		}
	})

	u, err := userModule.Repo.GetByUsername(ctx, tenantID, *username)
	if err != nil {
		return fmt.Errorf("look up %q in tenant %d: %w", *username, tenantID, err)
	}

	password, err := obtainPassword(*generate, *fromStdin)
	if err != nil {
		return err
	}

	// must_change_pwd is forced, not offered: the password reaches the operator
	// through a terminal, a scrollback and possibly a ticket, so it is already
	// shared by the time it is used once.
	mustChange := true
	if err := svc.ResetPassword(ctx, u.ID, &user.ResetPasswordRequest{
		NewPassword: password,
		MustChange:  &mustChange,
	}); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}

	// Written synchronously, not published: the event bus starts a goroutine
	// per handler and this process exits immediately afterwards, so a published
	// event would be lost before it reached the database. Routing the reset
	// through the product instead of an UPDATE statement is only worth
	// something if it leaves the trail an UPDATE does not.
	auditRepo := audit.NewGormRepository(a.DB)
	auditSvc := audit.NewService(auditRepo, a.IDGen, a.EventBus, a.Logger, tenantID)
	auditSvc.SetChainBridge(a.DB, audit.NewCapturer(a.IDGen))
	// `method` is the detail field the audit schema already allows through for
	// this event (schema.go's projection drops anything else), so it is where
	// "this did not come from a console session" has to be recorded.
	method := "cli-out-of-band"
	if *unlock {
		method = "cli-out-of-band+unlock"
	}
	auditSvc.RecordOutOfBand(ctx, "user.password_changed", "user", u.ID, u.Username,
		map[string]any{
			"user_id":   u.ID,
			"tenant_id": tenantID,
			"method":    method,
		})

	if *unlock {
		// Separate from the reset because status and credentials are separate
		// decisions — an account may be locked for a reason unrelated to the
		// password, and this command should not silently reverse that.
		if err := userModule.Repo.UpdateStatus(ctx, u.ID, statusActiveCLI); err != nil {
			return fmt.Errorf("unlock account: %w", err)
		}
	}

	// stdout, never the logger: the log redacts anything that looks like a
	// credential, so a generated password would reach the operator as "***" —
	// and defeating that filter to push a secret into the log pipeline is the
	// wrong trade.
	if *generate {
		fmt.Printf("password: %s\n", password)
	}
	fmt.Printf("reset %s (id=%d)%s; a password change is required at first sign-in\n",
		*username, u.ID, map[bool]string{true: " and unlocked", false: ""}[*unlock])
	return nil
}

// statusActiveCLI mirrors user.StatusActive. The user package exports it, but
// naming it here keeps the intent readable at the call site above.
const statusActiveCLI = 1

// obtainPassword resolves the new password from whichever input the operator
// chose. Prompting is the default because it keeps the value out of shell
// history, the process list and any log the terminal is piped into.
func obtainPassword(generate, fromStdin bool) (string, error) {
	switch {
	case generate:
		return generatePassword()
	case fromStdin:
		var pw string
		if _, err := fmt.Scanln(&pw); err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		if strings.TrimSpace(pw) == "" {
			return "", errors.New("empty password on stdin")
		}
		return pw, nil
	default:
		return promptPassword()
	}
}

// promptPassword reads the password twice without echo. Requires a TTY, which
// under Kubernetes means `kubectl exec -it`; without one the error says so
// rather than silently reading a truncated line.
func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal available for the password prompt: " +
			"run with `kubectl exec -it`, or pass -stdin / -generate")
	}
	fmt.Print("New password: ")
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Print("Repeat: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("the two passwords do not match")
	}
	if len(first) == 0 {
		return "", errors.New("empty password")
	}
	return string(first), nil
}

// generatePassword builds a password that satisfies every complexity policy the
// product can be configured with — one character drawn from each required class
// first, then filled from the union — so -generate never fails validation on a
// deployment that tightened the rules.
func generatePassword() (string, error) {
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnopqrstuvwxyz"
		digits  = "23456789"
		special = "!@#$%^&*-_=+"
		length  = 24
	)
	classes := []string{upper, lower, digits, special}
	all := upper + lower + digits + special

	out := make([]byte, 0, length)
	for _, c := range classes {
		ch, err := pick(c)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for len(out) < length {
		ch, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	// Shuffle so the guaranteed class characters are not always in front.
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("shuffle password: %w", err)
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("generate password: %w", err)
	}
	return set[n.Int64()], nil
}
