package example

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// GcpDecrypt unseals data through the google-cloud-go KMS client:
// kms.NewKeyManagementClient then client.Decrypt.
func GcpDecrypt(ctx context.Context, name string, blob []byte) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       name,
		Ciphertext: blob,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}