package transport

func normalizeParcel(id string) []byte {
	return []byte(id)
}

func protect(mode, payload string) []byte {
	return encrypt(mode, string(normalizeParcel(payload)), make([]byte, 32))
}

func ProtectParcel(id string) []byte {
	return protect("gcm", id)
}

func ProtectArchivedNote(note string) []byte {
	return protect("cbc", note)
}

func prepareExternal(kind, payload string) []byte {
	return protect(kind, payload)
}
