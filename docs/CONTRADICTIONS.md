# Cross-Layer Contradiction Detection (Pillar 4)

Hash Patch's fourth pillar introduces a second, independent detection layer:
**static deployed TLS/SSL configuration files** (`nginx.conf`, Apache `httpd.conf`,
Java `java.security` and `.properties` files) and analyzes them alongside
**source-code TLS declarations** (Python and Java source intent).

It detects **cross-layer policy contradictions** where the application's source
code expresses a strict cryptographic transport policy (e.g. TLS 1.3 minimum or
TLS 1.2+ only), but the deployed infrastructure configuration file permits
deprecated, weak, or broken protocols and cipher suites (e.g. TLS 1.0, TLS 1.1,
SSLv3, RC4, or NULL ciphers).

---

## 1. Supported Configuration Formats & Directives

All detection logic is driven by YAML rules in `rules/legacy_tls_config.yaml` and
`rules/tls_source_intent.yaml`. No directive names, algorithm names, or API patterns
are hardcoded in Python.

| Layer | Technology | Recognised Directives / APIs | Format Identifier |
| :--- | :--- | :--- | :--- |
| **Deployed Config** | **nginx** | `ssl_protocols`, `ssl_ciphers` | `nginx` |
| **Deployed Config** | **Apache httpd** | `SSLProtocol`, `SSLCipherSuite` | `apache` |
| **Deployed Config** | **Java / Properties** | `jdk.tls.client.protocols`, `jdk.tls.server.protocols`, `tls.protocols`, `tls.ciphers` | `java-properties` |
| **Source Intent** | **Python** | `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3`, `ssl.PROTOCOL_TLSv1_2`, etc. | `source-code-intent` |
| **Source Intent** | **Java** | `SSLContext.getInstance("TLSv1.3")`, `SSLContext.getInstance("TLSv1.2")`, etc. | `source-code-intent` |

If a configuration file does not contain any recognised directives or matches an unknown
format, it is silently ignored rather than guessed (consistent with Hash Patch's
evidence-or-refuse discipline).

---

## 2. Legacy TLS Definition & Authoritative Sources

The definitions of deprecated, insecure, or legacy transport cryptography are
centralized in `rules/legacy_tls_config.yaml`:

### Protocols
- **`SSLv2` (High severity)**: Prohibited by **RFC 6176**. Critically broken 1990s protocol.
- **`SSLv3` (High severity)**: Deprecated by **RFC 7568**. Vulnerable to POODLE and padding oracle attacks.
- **`TLSv1.0` (Medium severity)**: Deprecated by **RFC 8996**. Lacks modern AEAD cipher support; vulnerable to BEAST.
- **`TLSv1.1` (Medium severity)**: Deprecated by **RFC 8996**. Lacks modern AEAD cipher support.

### Ciphers
- **`NULL` / `aNULL` / `eNULL` (High severity)**: Unauthenticated or unencrypted ciphers.
- **`EXPORT` (High severity)**: 40/56-bit weakened export cryptography (vulnerable to FREAK/Logjam).
- **`DES` (High severity)**: 56-bit key broken classically.
- **`3DES` (High severity)**: 64-bit block size vulnerable to Sweet32 collision attacks.
- **`RC4` (High severity)**: Prohibited by **RFC 7465**. Keystream biases allow plaintext recovery.
- **`MD5` (High severity)**: Broken hash function for integrity/MAC.
- **`CBC` without AEAD (Medium severity)**: Vulnerable to Lucky13 and padding oracle attacks in TLS ≤ 1.2.

---

## 3. Same-Scope Correlation Discipline

A contradiction is only evaluated between source intent and deployed configuration
files that reside **within the same scan target and the same subproject scope**:

1. **Same-directory correlation**: If `app.py` and `nginx.conf` share the same directory,
   they are correlated directly.
2. **Subproject isolation**: In a multi-service repository or monorepo, files residing in
   `service-a/` will not correlate with configuration files in `service-b/`.
3. **No phantom contradictions**:
   - A deployed configuration file with `allows_legacy=True` but **no matching source intent**
     in its scope produces a `TlsConfigFinding`, but **zero contradiction findings** (there is
     no code policy being contradicted).
   - Strict source code with **no deployed configuration** in its scope produces **zero contradiction findings**.

---

## 4. CycloneDX 1.6 Architectural Decision: Properties vs Vulnerabilities

Cross-layer contradiction findings are emitted as structured `hash_patch:contradiction.*` properties on the BOM's `metadata.properties` rather than using CycloneDX 1.6's `vulnerabilities` array because a contradiction is a cross-layer policy divergence between co-located artifacts, not a component-level software flaw. The CycloneDX standard defines `vulnerabilities` specifically for security advisories and CVEs affecting identified components or services via CPEs/PURLs; forcing a configuration-versus-code policy mismatch into this array would require fabricating synthetic CVE identifiers and distorting the `affects` relationship to link two disparate files across layers. In contrast, namespacing contradictions under `metadata.properties` preserves strict semantic integrity, keeps CycloneDX components unpolluted, maintains full schema validity against the official CycloneDX 1.6 specification, and follows the exact `hash_patch:` property convention already established across all other detection pillars.

### Detailed Justification:
- **Semantic fit**: CycloneDX's standard `vulnerabilities` array is explicitly defined as
  *"Vulnerabilities identified in components or services"* (typically CVEs or security advisories
  affecting specific library versions via CPE or PURL). A policy divergence between application
  intent and a reverse proxy configuration is **not** a software flaw in a third-party library.
  Forcing it into `vulnerabilities` would require inventing synthetic CVE-like identifiers and
  abusing the `affects` relationship.
- **Namespace hygiene**: In Hash Patch, all non-standard and multi-layer findings are
  consistently namespaced under `hash_patch:` (e.g. `hash_patch:reachability`,
  `hash_patch:property.shelfLife.*`, `hash_patch:property.blastRadius.*`).
- **Standard validity**: Emitting each contradiction as a structured JSON record under
  `metadata.properties` (with name `hash_patch:contradiction.<id>`) validates 100% cleanly
  against the official vendored CycloneDX 1.6 schema without network lookups or schema hacks.

---

## 5. Honesty Caveat: Not Live Monitoring

> [!WARNING]
> **Static Repository Analysis Only — Not Live Network Probing**
>
> Pillar 4 inspects configuration files and source code statically co-located within the
> target path supplied to `hash-patch scan`.
>
> It does **NOT**:
> - Make network connections or probe live IP/DNS endpoints.
> - Inspect runtime socket negotiations or TLS handshakes.
> - Know about configurations applied out-of-band (e.g. cloud provider load balancers,
>   Kubernetes ingress controllers, CDN edge rules, or central configuration management
>   repos) that are not checked into the scanned repository.
>
> A scan reporting `0 cross-layer contradictions` proves only that the repository's own
> checked-in configuration files do not contradict its checked-in source code.
