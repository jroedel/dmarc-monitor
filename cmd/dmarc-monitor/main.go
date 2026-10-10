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
//	dmarc-monitor -cron               what the crontab runs: lock, one cycle, deploy notice
//	dmarc-monitor -watch              poll forever
package main

import (
	"cmp"
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
)

// version and commit are stamped at link time by deploy/deploy.sh:
//
//	go build -ldflags "-X main.version=v0.1.5-3-gabc1234 -X main.commit=abc1234..."
//
// version is git describe's answer, so it names the last tag and how far past
// it the build is; commit is the full hash the deploy notice links to. An
// unstamped build reports "dev" and no commit.
var (
	version = "dev"
	commit  = ""
)

// sourceRepo is where a commit hash is looked up, for the link in the deploy
// notice.
const sourceRepo = "https://github.com/jroedel/dmarc-monitor"

// scheduleZone is the timezone the crontab line deploy/deploy.sh installs
// schedules in. The crontab guard asks the system for the hour in this zone,
// and if the zone cannot be resolved the shell's date silently answers in UTC
// instead — which would move every run by two hours in winter and three in
// summer, without an error anywhere. -check resolves it here so that failure
// is found at install time by someone who is looking, rather than months later
// by nobody.
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
	showVersion bool
	testAlert   bool
}

func run() error {
	var f flags

	flag.StringVar(&f.credentials, "credentials", "", "path to the credentials file (default: credentials.env beside the binary)")
	flag.StringVar(&f.state, "state", "", "path to the state file (default: state.json beside the binary)")
	flag.BoolVar(&f.initCreds, "init-credentials", false, "write a commented credentials template and exit")
	flag.BoolVar(&f.check, "check", false, "verify the credentials parse and both servers are reachable, then exit; sends nothing")
	flag.BoolVar(&f.testAlert, "test-alert", false, "send a real test message to the alert recipients and print its Message-ID, then exit")
	flag.BoolVar(&f.once, "once", true, "run one cycle and exit")
	flag.BoolVar(&f.watch, "watch", false, "poll on the configured interval until interrupted")
	flag.BoolVar(&f.dryRun, "dry-run", false, "print the alert that would be sent; send nothing, change nothing")
	flag.BoolVar(&f.includeSeen, "include-seen", false, "examine every message, not only unread ones (for a first run over an existing archive)")
	flag.BoolVar(&f.cron, "cron", false, "what a crontab entry runs: take the lock, run one cycle, exit; mails once when a new build is deployed")
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

	alerts := alertbus.NewBusiness(log, alertStore, alertbus.Config{
		From:          cfg.AlertFrom,
		To:            cfg.AlertTo,
		SubjectPrefix: cfg.AlertSubjectPrefix,
	})

	// Both are diagnostics that exit instead of running a cycle, and they
	// compose. -check proves the relay accepts a connection and a password;
	// -test-alert proves a message survives the rest of the trip to a human.
	// Running them together answers both questions in the order they fail in.
	if f.check || f.testAlert {
		if f.check {
			if err := check(ctx, log, cfg, reportStore, alertStore); err != nil {
				return err
			}
		}

		if !f.testAlert {
			return nil
		}

		return testAlert(ctx, alerts, f.dryRun)
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

	// Only under -cron, because that is what the server runs: a person trying
	// a new build by hand with -once is not a deploy, and must not use up the
	// notice the scheduled run is about to send.
	//
	// Before the cycle, not after: this mail is proof that a new build reached
	// the machine, and it should arrive even if the cycle that follows then
	// fails to reach the mailbox.
	if f.cron {
		announceDeploy(ctx, log, alerts, state, cfg.NotifyOnUpdate, f.dryRun)
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

	// Only under -cron, for the same reason as the deploy notice: a person
	// running a cycle by hand sees its error on their own terminal.
	if f.cron {
		trackHealth(ctx, log, alerts, state, err, f.dryRun)
	}

	if err != nil {
		return err
	}

	report(result, f.dryRun)

	return nil
}

// announceDeploy mails the deploy notice on the first scheduled run of a new
// build, or prints it under -dry-run.
//
// The deploy replaces the binary from outside and does not run a cycle, so this
// run is the first moment anything on the server knows a new build landed. The
// version is recorded whether or not the notice is wanted, so that turning
// ALERT_ON_UPDATE back on later does not announce a deploy from weeks ago.
//
// Failures are logged and swallowed. The notice is a convenience -- the deploy
// already happened and its own log records it -- and a relay that is refusing
// mail must not stop the cycle that is about to look for reports. The version
// is recorded before the mail goes, for the same reason: a relay that is down
// costs one notice, rather than a notice on every run until it comes back.
func announceDeploy(ctx context.Context, log *slog.Logger, alerts *alertbus.Business, state *checkpoint.Store, enabled, dryRun bool) {
	previous := state.RunningVersion()
	if previous == version {
		return
	}

	if !dryRun {
		if err := state.RecordVersion(version); err != nil {
			log.Warn("could not record the running version; the deploy notice may repeat", "err", err)
		}
	}

	log.Info("first scheduled run of a new build", "from", previous, "to", version, "commit", commit)

	if !enabled {
		return
	}

	path, err := os.Executable()
	if err != nil {
		path = "the installed binary"
	}

	sendNotice(ctx, log, alerts, "deploy notice", deployNotice(deployed{from: previous, to: version, commit: commit}, path), dryRun)
}

// trackHealth tells the webmaster when scheduled cycles start failing, again
// about once a day while they keep failing, and once when they recover.
//
// A monitor that has stopped reading its mailbox is silent, and silence is
// what a monitor with nothing to report looks like too. cron's own failure
// mail cannot be relied on to break that silence: the crontab is shared, and
// where its MAILTO goes is not this program's to decide. So the program says
// so itself, through the relay it already has. It cannot when the relay is
// what broke; the failure is still recorded, and the next run tries again.
//
// The outage is written to state.json the moment it is noticed, because a
// failed cycle never reaches the save at the end of a good one. Under -dry-run
// the mail is printed and nothing is recorded. A cycle stopped by a signal is
// neither a failure nor a recovery.
func trackHealth(ctx context.Context, log *slog.Logger, alerts *alertbus.Business, state *checkpoint.Store, cycleErr error, dryRun bool) {
	now := time.Now()

	switch {
	case errors.Is(cycleErr, context.Canceled):
		return

	case cycleErr != nil:
		if !dryRun {
			if err := state.RecordFailure(now); err != nil {
				log.Warn("could not record the failed run", "err", err)
			}
		}

		since := now
		if o, failing := state.Failing(); failing {
			since = o.Since
		}

		if !dryRun && !state.FailureMailDue(now) {
			log.Info("still failing; the webmaster was told within the last day", "since", since)

			return
		}

		sent := sendNotice(ctx, log, alerts, "failure notice", failureNotice(cycleErr, since), dryRun)
		if sent && !dryRun {
			if err := state.MarkFailureMailed(now); err != nil {
				log.Warn("could not record the failure mail; it may repeat at the next run", "err", err)
			}
		}

	default:
		o, failing := state.Failing()
		if !failing {
			return
		}

		if !dryRun {
			if _, _, err := state.RecordRecovery(); err != nil {
				log.Warn("could not record the recovery; the recovery mail may repeat", "err", err)
			}
		}

		log.Info("running again after failed runs", "since", o.Since)

		// Nobody was told it was broken -- every failure mail failed too --
		// so a mail saying it is fixed would be the first anyone heard of it.
		if o.Mailed.IsZero() {
			return
		}

		sendNotice(ctx, log, alerts, "recovery notice", recoveryNotice(o, now), dryRun)
	}
}

// sendNotice mails a notice, or prints it under -dry-run, and reports whether
// it went (or would have).
//
// Failures are logged and swallowed. Every notice is about the program rather
// than about a report, and none of them may stop a cycle or change its exit
// status: that is what the reports and cron.log are for.
func sendNotice(ctx context.Context, log *slog.Logger, alerts *alertbus.Business, what string, notice alertbus.Notice, dryRun bool) bool {
	if dryRun {
		msg, err := alerts.RenderNotice(notice)
		if err != nil {
			log.Warn("could not render the "+what, "err", err)

			return false
		}

		fmt.Printf("DRY RUN — the %s that would be sent:\n\nTo:         %s\nMessage-ID: %s\nSubject:    %s\n\n%s\n",
			what, joinAddresses(msg), msg.ID, msg.Subject, msg.Body)

		return true
	}

	if _, err := alerts.Notify(ctx, notice); err != nil {
		log.Warn("could not send the "+what, "err", err)

		return false
	}

	return true
}

// testAlert sends the message this program exists to send, on demand.
//
// -check already proves the relay is reachable and the password is accepted.
// That is a smaller claim than it looks: a relay can authenticate happily and
// still have the receiving side drop the result into a spam folder, and a
// monitor whose mail is being filtered is indistinguishable from a monitor with
// nothing to report. The only way to tell them apart is to send something and
// go looking for it.
//
// So this is not a simulation. It goes through the same rendering, the same
// headers, the same encoding and the same relay as a real alert, and prints the
// Message-ID afterwards — because the next question after "did it arrive?" is
// always "then where did it go?", and that is the string a mail log is searched
// by.
func testAlert(ctx context.Context, alerts *alertbus.Business, dryRun bool) error {
	notice := testNotice()

	if dryRun {
		msg, err := alerts.RenderNotice(notice)
		if err != nil {
			return err
		}

		fmt.Printf("DRY RUN — the test message that would be sent:\n\nTo:         %s\nMessage-ID: %s\nSubject:    %s\n\n%s\n",
			joinAddresses(msg), msg.ID, msg.Subject, msg.Body)

		return nil
	}

	msg, err := alerts.Notify(ctx, notice)
	if err != nil {
		return err
	}

	fmt.Println("Test message sent.")
	fmt.Printf("  Message-ID  %s\n", msg.ID)
	fmt.Printf("  to          %s\n", joinAddresses(msg))
	fmt.Println()
	fmt.Println("The relay accepted it. If it does not arrive, that Message-ID is what to")
	fmt.Println("search the mail server's log for — and check the spam folder first.")

	return nil
}

// testNotice is the body of that message.
//
// It says plainly that a person asked for it, because the recipient is the
// webmaster and every other mail this program sends means something needs
// doing. An unexplained test message from a monitoring tool is indistinguishable
// from the monitoring tool malfunctioning.
func testNotice() alertbus.Notice {
	host := hostname()

	var b strings.Builder

	fmt.Fprintf(&b, "This is a test message from dmarc-monitor on %s.\n\n", host)
	fmt.Fprintf(&b, "  version  %s\n", version)
	fmt.Fprintf(&b, "  sent     %s\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("\nSomebody ran 'dmarc-monitor -test-alert' by hand. Nothing is wrong, no\n")
	b.WriteString("DMARC report prompted this, and there is nothing to do about it.\n\n")
	b.WriteString("It was rendered and sent exactly the way a real alert is — same headers,\n")
	b.WriteString("same encoding, same relay — so if this reached you, a real alert will too.\n")

	return alertbus.Notice{
		Subject: fmt.Sprintf("test message from %s", host),
		Body:    b.String(),
	}
}

// deployed describes the build change a deploy notice reports.
type deployed struct {
	from   string
	to     string
	commit string
}

// deployNotice is the mail sent on the first run of a new build.
//
// Short on purpose. Its whole job is to say that the pipeline reached this
// machine, so it names the versions, the host and the file, and stops. Anyone
// who wants more has the commit linked.
func deployNotice(d deployed, path string) alertbus.Notice {
	host := hostname()

	var b strings.Builder

	fmt.Fprintf(&b, "dmarc-monitor is running a newly deployed build on %s.\n\n", host)
	// Every installation that predates the deploy notice has no version
	// recorded, so the first notice after the switch would otherwise show an
	// empty field where the old version belongs.
	fmt.Fprintf(&b, "  from     %s\n", cmp.Or(d.from, "(not recorded)"))
	fmt.Fprintf(&b, "  to       %s\n", d.to)
	fmt.Fprintf(&b, "  binary   %s\n", path)
	if d.commit != "" {
		fmt.Fprintf(&b, "  commit   %s/commit/%s\n", sourceRepo, d.commit)
	}
	b.WriteString("\nThis is the new build's first scheduled run; it goes on to read the mailbox as usual.\n")
	b.WriteString("\nThis mail means the deployment pipeline works. Set ALERT_ON_UPDATE=false to stop it.\n")

	return alertbus.Notice{
		Subject: fmt.Sprintf("deployed %s on %s", d.to, host),
		Body:    b.String(),
	}
}

// failureNotice is the mail sent when scheduled runs fail.
//
// It leads with what the failure means rather than what it was, because the
// reader's first question is "is my mail being watched?", and the answer is
// no. The error follows, verbatim: it is the only diagnosis the program has.
func failureNotice(cycleErr error, since time.Time) alertbus.Notice {
	host := hostname()

	var b strings.Builder

	fmt.Fprintf(&b, "dmarc-monitor's scheduled run on %s failed.\n\n", host)
	b.WriteString("Until this is fixed, no DMARC report is being read, so nothing will be\n")
	b.WriteString("alerted on. This mail repeats about once a day while it lasts, and one\n")
	b.WriteString("more follows when a run succeeds again.\n\n")
	fmt.Fprintf(&b, "  failing since  %s\n", since.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "  version        %s\n\n", version)
	fmt.Fprintf(&b, "The error:\n\n%s\n\n", indent(cycleErr.Error()))
	b.WriteString("To look into it, from the project's checkout:\n\n")
	b.WriteString("  make prod-check   # are the mailbox and the relay reachable? sends nothing\n")
	b.WriteString("  make prod-logs    # the recent runs\n")

	return alertbus.Notice{
		Subject: fmt.Sprintf("run failed on %s", host),
		Body:    b.String(),
	}
}

// recoveryNotice is the mail sent when a run succeeds after failure mail went
// out. Without it, the last word on the subject would be "broken".
func recoveryNotice(o checkpoint.Outage, now time.Time) alertbus.Notice {
	host := hostname()

	var b strings.Builder

	fmt.Fprintf(&b, "dmarc-monitor's scheduled run on %s succeeded again.\n\n", host)
	fmt.Fprintf(&b, "  failing since  %s\n", o.Since.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "  running again  %s\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "  for            %s\n\n", now.Sub(o.Since).Round(time.Minute))
	b.WriteString("Reports that arrived meanwhile were read by this run, and anything they\n")
	b.WriteString("warranted has been alerted on in its own mail.\n")

	return alertbus.Notice{
		Subject: fmt.Sprintf("running again on %s", host),
		Body:    b.String(),
	}
}

// indent sets an error's text off from the prose around it, line by line,
// since a joined error spans several.
func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// hostname names the machine in a notice, or says it could not.
func hostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "an unknown host"
	}

	return host
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
	fmt.Printf("The deployed crontab line runs at 08:00 and 20:00 %s, which is %s and %s here today.\n",
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
	out := make([]string, 0, len(msg.To))
	for _, to := range msg.To {
		out = append(out, to.String())
	}

	return strings.Join(out, ", ")
}

// resolve takes an explicit path or falls back to the package default.
func resolve(explicit string, fallback func() (string, error)) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	return fallback()
}
