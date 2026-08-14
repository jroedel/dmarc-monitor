//go:build !unix

package lockfile

import (
	"errors"
	"os"
)

// flock has no portable equivalent outside unix. Rather than pretend the lock
// was taken — which would let two copies run and corrupt the state file —
// building for such a platform fails at the one call site that needs it.
func flock(_ *os.File) error {
	return errors.New("lockfile: file locking is not implemented on this platform")
}
