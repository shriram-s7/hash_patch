package example

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// KmsEncrypt seals data using AWS KMS. The client is constructed with
// kms.New(sess) then used with client.Encrypt.
func KmsEncrypt(plaintext []byte) ([]byte, error) {
	sess := session.Must(session.NewSession())
	client := kms.New(sess)
	out, err := client.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String("alias/protect"),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// KmsDecrypt unseals data using the same client shape with client.Decrypt.
func KmsDecrypt(blob []byte) ([]byte, error) {
	client := kms.New(session.New())
	out, err := client.Decrypt(&kms.DecryptInput{
		KeyId:         aws.String("alias/protect"),
		CiphertextBlob: blob,
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}