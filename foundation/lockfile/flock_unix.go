//go:build unix

package lockfile

import (
	"os"
	"syscall"
)

// flock takes an exclusive, non-blocking lock on the open file. The lock lives
// on the file description, so the kernel drops it when the process exits —
// which is the property that makes this safe under cron.
func flock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch err {
	case nil:
		return nil
	case syscall.EWOULDBLOCK:
		return ErrHeld
	default:
		return err
	}
}
