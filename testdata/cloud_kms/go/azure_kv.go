package example

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// AzureEncrypt seals data through Azure Key Vault keys crypto:
// azkeys.NewClient then client.Encrypt.
func AzureEncrypt(ctx context.Context, keyURL string, payload []byte) ([]byte, error) {
	client, err := azkeys.NewClient(nil, nil)
	if err != nil {
		return nil, err
	}
	params := azkeys.EncryptParameters{
		Algorithm: azkeys.EncryptionAlgorithmRSAOAEP,
		Value:     payload,
	}
	result, err := client.Encrypt(ctx, keyURL, params, nil)
	if err != nil {
		return nil, err
	}
	return result.Ciphertext, nil
}