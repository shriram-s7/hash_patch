package p53

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
