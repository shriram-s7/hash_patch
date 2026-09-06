package main

import (
	"net/http"
	"harborline/gateway/internal/tokens"
	"harborline/gateway/internal/customer"
	"harborline/gateway/internal/transport"
)

func main() {
	http.HandleFunc("/token", tokens.Issue)
	http.HandleFunc("/account", customer.StoreAccount)
	http.HandleFunc("/parcel", func(w http.ResponseWriter, r *http.Request) {
		w.Write(transport.ProtectParcel(r.URL.Query().Get("id")))
	})
	http.HandleFunc("/note", func(w http.ResponseWriter, r *http.Request) {
		w.Write(transport.ProtectArchivedNote(r.URL.Query().Get("note")))
	})
	http.ListenAndServe(":8080", nil)
}
