package example

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// ImportOnly returns a KMS client but never calls an operation on it -- it
// must produce ZERO cloud-key findings (client construction alone is never
// a finding).
func ImportOnly(sess *session.Session) *kms.KMS {
	return kms.New(sess)
}