package feeds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type epssHashKey struct{}

// WithEPSSPreviousHash attaches the last stored EPSS content hash to the context.
func WithEPSSPreviousHash(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, epssHashKey{}, hash)
}

func epssPreviousHash(ctx context.Context) string {
	v, _ := ctx.Value(epssHashKey{}).(string)
	return v
}

// EPSSBodySHA returns a stable hash of the raw EPSS gzip payload.
func EPSSBodySHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

// IsUnchanged returns true when err indicates the feed payload is unchanged.
func IsUnchanged(err error) bool {
	return errors.Is(err, ErrUnchanged)
}
