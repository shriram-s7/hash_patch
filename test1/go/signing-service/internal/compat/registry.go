package compat

var Profiles = map[string]string{
    "default": "RSA",
    "legacy":  "DSA",
    "elliptic": "ECDSA",
}

func Resolve(name string) string {
    if x, ok := Profiles[name]; ok {
        return x
    }
    return Profiles["default"]
}
