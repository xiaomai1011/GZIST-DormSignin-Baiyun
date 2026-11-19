//go:build !windows

package browserhost

import "os"

// writeStateFile writes through a 0600 temp file in the same directory and
// renames it into place, so the secret never appears with wider permissions.
func writeStateFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
