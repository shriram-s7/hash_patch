# Cross-language contracts

These are represented as source-level contracts, not executable IPC.

1. Python `build_payment()` emits:
   - signature algorithm
   - key reference
   - exchange family
   - envelope family

2. Go `Dispatch()` consumes the conceptual request and selects:
   - legacy vs normal policy
   - exchange path
   - signature family

3. C `dispatch_exchange()` is the native compatibility endpoint.

4. Java `PaymentWorkflow` is an application-level producer that combines:
   - RSA/ECDSA authentication
   - AES-GCM or legacy AES-CBC storage

The corpus intentionally does not pretend that static source alone proves a runtime
network call. A CBOM tool should represent confidence rather than inventing certainty.
