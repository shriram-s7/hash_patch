package legacy

const (
    DocumentationOnly = "RSA-1024"
    Retired = "3DES"
)

// NeverReachable exists to force the analyzer to distinguish declarations
// from runtime use.
func NeverReachable() string {
    return DocumentationOnly + ":" + Retired
}
