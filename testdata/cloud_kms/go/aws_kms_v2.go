package example

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KmsEncryptV2 seals data using AWS KMS SDK v2: kms.NewFromConfig then
// kmsClient.Encrypt.
func KmsEncryptV2(ctx context.Context, plaintext []byte) ([]byte, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	kmsClient, err := kms.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	out, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     "alias/protect",
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}