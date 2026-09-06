package p1

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
