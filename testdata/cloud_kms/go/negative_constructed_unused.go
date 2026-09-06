package example

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// ConstructedUnused builds a client but never calls an operation -- must
// produce ZERO cloud-key findings.
func ConstructedUnused() {
	client := kms.New(session.New())
	_ = client
}