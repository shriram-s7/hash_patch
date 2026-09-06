package main

import (
    "fmt"
    "edge-gateway/internal/routing"
    "edge-gateway/internal/crypto"
)

func main() {
    req := routing.Request{Partner: "old-bank", Body: []byte("transaction")}
    peer := &crypto.PeerMaterial{Public: []byte("peer"), Private: []byte("local")}
    out, _ := routing.Dispatch(req, peer)
    fmt.Println(out)
}
