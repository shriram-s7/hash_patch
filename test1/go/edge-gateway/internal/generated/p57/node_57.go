package p57

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
