package example

import (
	"bytes"
	"io"
	"net/http"
)

// Upload posts to a plain HTTP endpoint whose URL and payload mention
// "key"/"encrypt" without any cloud KMS SDK client -- must produce ZERO
// cloud-key findings.
func Upload() error {
	encrypt := "encrypt"
	key := "demo-key"
	body := bytes.NewBufferString("{}")
	resp, err := http.Post("https://example.com/v1/keys", "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}