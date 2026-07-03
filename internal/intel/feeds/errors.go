package feeds

import "errors"

// ErrUnchanged indicates the remote feed payload matches the last successful collect.
var ErrUnchanged = errors.New("feed unchanged")
