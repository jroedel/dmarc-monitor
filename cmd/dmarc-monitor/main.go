// Command dmarc-monitor reads DMARC aggregate reports from a mailbox and mails
// the webmaster when — and only when — something needs doing about them.
//
// It is built to be run from a systemd timer or cron. The default mode does one
// cycle and exits; -watch keeps it resident. Either way it is silent unless it
// has something to say, which is the entire product.
//
//	dmarc-monitor -init-credentials   write the credentials template and stop
//	dmarc-monitor -check              prove the mailbox and relay are reachable
//	dmarc-monitor -once -dry-run      run a full cycle, print the alert, send nothing
//	dmarc-monitor -once               run a full cycle for real
//	dmarc-monitor -cron               what the crontab runs: lock, self-update, one cycle
//	dmarc-monitor -watch              poll forever
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jroedel/dmarc-monitor/app/monitor"
	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/domain/alert/stores/smtpstore"
	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/business/domain/report/stores/imapstore"
	"github.com/jroedel/dmarc-monitor/business/domain/triage/stores/kronkllm"
	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
	"github.com/jroedel/dmarc-monitor/foundation/checkpoint"
	"github.com/jroedel/dmarc-monitor/foundation/config"
	"github.com/jroedel/dmarc-monitor/foundation/lockfile"
	"github.com/jroedel/dmarc-monitor/foundation/logger"
	"github.com/jroedel/dmarc-monitor/foundation/selfupdate"
)

// version is stamped at link time by the release build:
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// An unstamped build reports "dev" and is treated by the updater as older than
// any published release, so a hand-built binary left on a server adopts the
// real one at the next run.
var version = selfupdate.DevVersion

// updateRepo is where updates come from. A constant rather than a setting: a
// credentials file that could redirect the update source would turn a mail
// misconfiguration into arbitrary code execution.
const updateRepo = "jroedel/dmarc-monitor"

// scheduleZone is the timezone deploy/crontab.example schedules in. The crontab
// guard asks the system for the hour in this zone, and if the zone cannot be
// resolved the shell's date silently answers in UTC instead — which would move
// every run by two hours in winter and three in summer, without an error
// anywhere. -check resolves it here so that failure is found at install time by
// someone who is looking, rather than months later by nobody.
const scheduleZone = "America/Chicago"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dmarc-monitor: %v\n", err)
		os.Exit(1)
	}
}

type flags struct {
	credentials string
	state       string
	initCreds   bool
	check       bool
	once        bool
	watch       bool
	dryRun      bool
	includeSeen bool
	debug       bool
	logFormat   string
	cron        bool
	noUpdate    bool
	showVersion bool
}

func run() error {
	var f flags

	flag.StringVar(&f.credentials, "credentials", "", "path to the credentials file (default: credentials.env beside the binary)")
	flag.StringVar(&f.state, "state", "", "path to the state file (default: state.json beside the binary)")
	flag.BoolVar(&f.initCreds, "init-credentials", false, "write a commented credentials template and exit")
	flag.BoolVar(&f.check, "check", false, "verify the credentials parse and both servers are reachable, then exit")
	flag.BoolVar(&f.once, "once", true, "run one cycle and exit")
	flag.BoolVar(&f.watch, "watch", false, "poll on the configured interval until interrupted")
	flag.BoolVar(&f.dryRun, "dry-run", false, "print the alert that would be sent; send nothing, change nothing")
	flag.BoolVar(&f.includeSeen, "include-seen", false, "examine every message, not only unread ones (for a first run over an existing archive)")
	flag.BoolVar(&f.cron, "cron", false, "what a crontab entry runs: take the lock, self-update, run one cycle, exit")
	flag.BoolVar(&f.noUpdate, "no-update", false, "with -cron, skip the self-update check")
	flag.BoolVar(&f.showVersion, "version", false, "print the version and exit")
	flag.BoolVar(&f.debug, "debug", false, "log at debug level")
	flag.StringVar(&f.logFormat, "log", "text", "log format: text or json")
	flag.Parse()

	if f.showVersion {
		fmt.Printf("dmarc-monitor %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())

		return nil
	}

	log := logger.New(os.Stderr, logger.Format(f.logFormat), f.debug)

	credentialsPath, err := resolve(f.credentials, config.DefaultPath)
	if err != nil {
		return err
	}

	if f.initCreds {
		return initCredentials(credentialsPath)
	}

	statePath, err := resolve(f.state, checkpoint.DefaultPath)
	if err != nil {
		return err
	}

	var (
		update  installed
		updated bool
	)

	if f.cron {
		lock, err := lockfile.Acquire(filepath.Join(filepath.Dir(statePath), "run.lock"))
		if errors.Is(err, lockfile.ErrHeld) {
			log.Info("another run is still going; leaving it to finish")

			return nil
		}
		if err != nil {
			return err
		}
		defer lock.Release()

		// Before the config is loaded, so that a server whose credentials are
		// not filled in yet still picks up new builds.
		if !f.noUpdate {
			update, updated = updateCheck(context.Background(), log)
		}
	}

	cfg, err := config.Load(credentialsPath)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			// On a server this is the first scheduled run after the crontab
			// entry was installed. Leaving the template behind means the only
			// remaining step is to fill it in — the binary bootstrapped
			// everything it possibly could.
			if f.cron {
				if initErr := config.Init(credentialsPath); initErr == nil {
					return fmt.Errorf("%w\n\nA template has been written there. Fill in the mailbox and relay credentials", err)
				}
			}

			return fmt.Errorf("%w\n\nRun 'dmarc-monitor -init-credentials' to write a template there, then fill it in", err)
		}

		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reportStore := imapstore.NewStore(log, imapstore.Config{
		Host:        cfg.IMAPHost,
		Port:        cfg.IMAPPort,
		Username:    cfg.IMAPUsername,
		Password:    cfg.IMAPPassword,
		Mailbox:     cfg.IMAPMailbox,
		STARTTLS:    cfg.IMAPSecurity == config.SecuritySTARTTLS,
		MarkSeen:    cfg.MarkSeen,
		MoveTo:      cfg.MoveTo,
		IncludeSeen: f.includeSeen,
		DryRun:      f.dryRun,
	})

	alertStore := smtpstore.NewStore(log, smtpstore.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		Security: string(cfg.SMTPSecurity),
	})

	if f.check {
		return check(ctx, log, cfg, reportStore, alertStore)
	}

	state, err := checkpoint.Open(statePath)
	if err != nil {
		return err
	}

	var explainer triagebus.Explainer
	if cfg.LLMEnabled {
		explainer = kronkllm.NewClient(kronkllm.Config{
			Endpoint: cfg.LLMEndpoint,
			Model:    cfg.LLMModel,
			Timeout:  cfg.LLMTimeout,
		})

		log.Info("using local model for alert narratives", "endpoint", cfg.LLMEndpoint, "model", cfg.LLMModel)
	}

	alerts := alertbus.NewBusiness(log, alertStore, alertbus.Config{
		From:          cfg.AlertFrom,
		To:            cfg.AlertTo,
		SubjectPrefix: cfg.AlertSubjectPrefix,
	})

	// Sent before the cycle, not after: this mail is proof that a new build
	// reached the machine, and it should arrive even if the cycle that follows
	// then fails to reach the mailbox.
	if updated && cfg.NotifyOnUpdate {
		notify(ctx, log, alerts, update, f.dryRun)
	}

	m := monitor.New(
		log,
		reportbus.NewBusiness(reportStore),
		triagebus.NewBusiness(log, triagebus.Thresholds{
			FailureRate:     cfg.FailureRateThreshold,
			MinimumVolume:   cfg.MinimumVolume,
			NewSourceVolume: cfg.NewSourceVolume,
		}, explainer),
		alerts,
		state,
		monitor.Config{
			Floor:    cfg.AlertFloor,
			Cooldown: cfg.AlertCooldown,
			DryRun:   f.dryRun,
		},
	)

	if f.watch && !f.cron {
		return m.Run(ctx, cfg.PollInterval)
	}

	result, err := m.RunOnce(ctx)
	if err != nil {
		return err
	}

	report(result, f.dryRun)

	return nil
}

// update checks for a newer published release and installs it.
//
// Every failure here is logged and swallowed. An update is a convenience; the
// monitor's job is to read the mailbox, and it can do that perfectly well on
// the build it already has. GitHub being unreachable must never be the reason a
// webmaster is not told their mail is being rejected.
//
// The new binary lands on disk but does not take effect until the next cron
// run. Nothing is re-executed mid-cycle: a program that swapped itself out
// halfway through reading a mailbox would be a much harder thing to reason
// about than one that is simply newer tomorrow morning.
// installed describes an update that landed, for the notice sent afterwards.
type installed struct {
	from string
	to   string
	url  string
}

func updateCheck(ctx context.Context, log *slog.Logger) (installed, bool) {
	updater := selfupdate.New(selfupdate.Config{
		Repo:           updateRepo,
		CurrentVersion: version,
		AssetName:      fmt.Sprintf("dmarc-monitor-%s-%s", runtime.GOOS, runtime.GOARCH),
	})

	release, available, err := updater.Latest(ctx)
	switch {
	case err != nil:
		log.Warn("update check failed; carrying on with the current build", "version", version, "err", err)

		return installed{}, false
	case !available:
		log.Debug("no newer release", "version", version)

		return installed{}, false
	}

	log.Info("installing a newer release", "from", version, "to", release.Version, "url", release.URL)

	if err := updater.Apply(ctx, release); err != nil {
		log.Warn("update failed; carrying on with the current build", "version", version, "err", err)

		return installed{}, false
	}

	log.Info("update installed; it takes effect at the next run", "version", release.Version)

	return installed{from: version, to: release.Version, url: release.URL}, true
}

// notify mails the update notice, or prints it under -dry-run.
//
// Failures are logged and swallowed. The notice is a convenience — the update
// has already happened and the log already records it — and a relay that is
// refusing mail must not stop the cycle that is about to look for reports.
func notify(ctx context.Context, log *slog.Logger, alerts *alertbus.Business, update installed, dryRun bool) {
	path, err := os.Executable()
	if err != nil {
		path = "the installed binary"
	}

	notice := updateNotice(update, path)

	if dryRun {
		msg, err := alerts.RenderNotice(notice)
		if err != nil {
			log.Warn("could not render the update notice", "err", err)

			return
		}

		fmt.Printf("DRY RUN — the update notice that would be sent:\n\nTo:      %s\nSubject: %s\n\n%s\n",
			joinAddresses(msg), msg.Subject, msg.Body)

		return
	}

	if err := alerts.Notify(ctx, notice); err != nil {
		log.Warn("could not send the update notice; the update itself was fine", "err", err)
	}
}

// updateNotice is the mail sent when a new build lands.
//
// Short on purpose. Its whole job is to say that the pipeline reached this
// machine, so it names the versions, the host and the file, and stops. Anyone
// who wants more has the release page linked.
func updateNotice(update installed, path string) alertbus.Notice {
	host, err := os.Hostname()
	if err != nil {
		host = "an unknown host"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "dmarc-monitor updated itself on %s.\n\n", host)
	fmt.Fprintf(&b, "  from     %s\n", update.from)
	fmt.Fprintf(&b, "  to       %s\n", update.to)
	fmt.Fprintf(&b, "  binary   %s\n", path)
	fmt.Fprintf(&b, "  release  %s\n", update.url)
	b.WriteString("\nThe new build takes effect at the next scheduled run; this one finished on the old one.\n")
	b.WriteString("\nThis mail means the deployment pipeline works. Set ALERT_ON_UPDATE=false to stop it.\n")

	return alertbus.Notice{
		Subject: fmt.Sprintf("updated to %s on %s", update.to, host),
		Body:    b.String(),
	}
}

// initCredentials writes the template, and says where, because the path is
// derived and an operator should not have to guess it.
func initCredentials(path string) error {
	if err := config.Init(path); err != nil {
		if errors.Is(err, config.ErrExists) {
			return fmt.Errorf("%w\n\nNothing was changed. Edit it, or delete it first if you want a fresh template", err)
		}

		return err
	}

	fmt.Printf("Wrote a credentials template to %s (mode 0600).\n", path)
	fmt.Println("That is beside the binary, so one directory holds the whole installation.")
	fmt.Println()
	fmt.Println("Fill in these, at least:")
	fmt.Println("  IMAP_USERNAME, IMAP_PASSWORD   the mailbox the reports arrive in")
	fmt.Println("  SMTP_USERNAME, SMTP_PASSWORD   the relay the alert is sent through")
	fmt.Println("  ALERT_FROM, ALERT_TO           who the alert is from, and who reads it")
	fmt.Println()
	fmt.Println("Then: dmarc-monitor -check")

	return nil
}

// check proves both ends work. It is the first thing to run after filling in
// the credentials, and the thing to run when an alert did not arrive.
func check(ctx context.Context, log interface{ Info(string, ...any) }, cfg config.Config, reports *imapstore.Store, alerts *smtpstore.Store) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var problems []error

	if err := reports.Check(ctx); err != nil {
		problems = append(problems, err)
	}

	if err := alerts.Check(ctx); err != nil {
		problems = append(problems, err)
	}

	if cfg.LLMEnabled {
		client := kronkllm.NewClient(kronkllm.Config{
			Endpoint: cfg.LLMEndpoint,
			Model:    cfg.LLMModel,
			Timeout:  cfg.LLMTimeout,
		})

		// A model that is unreachable is a warning, never a failure: alerts go
		// out without it.
		if err := client.Check(ctx); err != nil {
			log.Info("local model is not reachable; alerts will be sent without a narrative", "err", err)
		}
	}

	if len(problems) > 0 {
		return errors.Join(problems...)
	}

	fmt.Println("Mailbox and relay both reachable. Alerts will go to:")
	for _, to := range cfg.AlertTo {
		fmt.Printf("  %s\n", to)
	}
	fmt.Printf("Nothing below %s will be sent.\n", cfg.AlertFloor)

	reportSchedule()

	return nil
}

// reportSchedule prints what the scheduled times mean on this machine, and
// complains if the timezone the crontab guard depends on is not installed.
func reportSchedule() {
	now := time.Now()

	loc, err := time.LoadLocation(scheduleZone)
	if err != nil {
		fmt.Printf("\nWARNING: this machine cannot resolve %s (%v).\n", scheduleZone, err)
		fmt.Println("The crontab guard asks for the hour in that zone; without it the shell's")
		fmt.Println("date falls back to UTC silently and the runs happen at the wrong times.")
		fmt.Println("Install tzdata:  sudo apt install tzdata")

		return
	}

	fmt.Printf("\nLocal time here is %s; in %s it is %s.\n",
		now.Format("15:04 MST"), scheduleZone, now.In(loc).Format("15:04 MST"))
	fmt.Printf("deploy/crontab.example runs at 08:00 and 20:00 %s, which is %s and %s here today.\n",
		scheduleZone,
		nextAt(now, loc, 8).Local().Format("15:04 MST"),
		nextAt(now, loc, 20).Local().Format("15:04 MST"))
}

// nextAt returns today's occurrence of an hour in loc, which is all that is
// needed to show an operator what the schedule means in their own clock.
func nextAt(now time.Time, loc *time.Location, hour int) time.Time {
	there := now.In(loc)

	return time.Date(there.Year(), there.Month(), there.Day(), hour, 0, 0, 0, loc)
}

// report prints the outcome of a single cycle to stdout. The log goes to
// stderr; this is the part a person asked for.
func report(result monitor.Result, dryRun bool) {
	switch {
	case result.Fetched == 0:
		fmt.Println("No unread messages in the mailbox.")

		return
	case result.Findings == 0:
		fmt.Printf("%d report(s) read, %d new. Nothing worth an alert.\n", result.Fetched, result.New)
		printSummary(result.Summary)

		if result.Suppressed > 0 {
			fmt.Printf("%d finding(s) suppressed by cooldown.\n", result.Suppressed)
		}

		return
	}

	if !dryRun {
		fmt.Printf("%d report(s) read, %d new, %d finding(s) at %s. Alert sent.\n",
			result.Fetched, result.New, result.Findings, result.Severity)

		return
	}

	fmt.Printf("%d report(s) read, %d new, %d finding(s) at %s.\n",
		result.Fetched, result.New, result.Findings, result.Severity)
	fmt.Printf("DRY RUN — nothing was sent, no message was flagged, no state was saved.\n\n")
	fmt.Printf("To:      %s\n", joinAddresses(result.Message))
	fmt.Printf("Subject: %s\n\n", result.Message.Subject)
	fmt.Println(result.Message.Body)
}

// printSummary shows what a quiet run actually looked at. Without it, "nothing
// worth an alert" is indistinguishable from a monitor that has silently stopped
// reading the mailbox — which is the failure mode nobody notices for months.
func printSummary(s triagebus.Summary) {
	if s.Volume == 0 {
		return
	}

	domains := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		domains = append(domains, d.String())
	}

	fmt.Printf("  %s over %s to %s\n",
		strings.Join(domains, ", "),
		s.Window.Begin.Format("2006-01-02"),
		s.Window.End.Format("2006-01-02"))
	fmt.Printf("  %d messages, %.1f%% passed DMARC, %d blocked, reported by %s\n",
		s.Volume, 100*s.PassRate(), s.Blocked, strings.Join(s.Reporters, ", "))
}

func joinAddresses(msg alertbus.Message) string {
	out := ""
	for i, to := range msg.To {
		if i > 0 {
			out += ", "
		}
		out += to.String()
	}

	return out
}

// resolve takes an explicit path or falls back to the package default.
func resolve(explicit string, fallback func() (string, error)) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	return fallback()
}
