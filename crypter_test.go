package crypter

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCrypter(t *testing.T) {
	goodKey := NewKey()
	badKey1 := Key(base64.RawURLEncoding.EncodeToString([]byte("badkey1")))
	badKey2 := Key("badkey2")
	clear := "small clear"

	_, err := NewBox(badKey1)
	require.Error(t, err, "bad key")

	_, err = NewBox(badKey2)
	require.Error(t, err, "bad key")

	box, err := NewBox(goodKey)
	require.NoError(t, err)

	_, err = box.Decrypt([]byte(clear))
	require.Error(t, err, "data too small")

	enc := box.Encrypt([]byte(clear))

	dec, err := box.Decrypt(enc)
	require.NoError(t, err)

	require.Equal(t, clear, string(dec))

	enc = box.Encrypt([]byte(nil))
	require.NoError(t, err)

	dec, err = box.Decrypt(enc)
	require.NoError(t, err)
	require.Len(t, dec, 0)
}
