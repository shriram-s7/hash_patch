-- schema.sql — Pillar 3 (Blast Radius) SQL DDL corpus fixture.
--
-- No detector in this codebase produces a CryptoAsset from a .sql file (see
-- hash_patch/analyze/blast_radius.py's "db_column name-pattern-only
-- fallback" note), so the `signature` column below fires through that
-- fallback path, not a real same-file CryptoAsset correlation. Expected
-- outcomes are recorded in tests/golden/blast_radius_manifest.json.

-- Stores ECDSA/RSA signatures for signed audit-log entries, hex-encoded
-- (1 byte per hex character, ASCII-range).
-- MUST FIRE: ML-DSA-65's 3309-byte signature does not fit in 512 bytes.
CREATE TABLE audit_log (
    id INT PRIMARY KEY,
    signature VARCHAR(512),
    created_at TIMESTAMP
);

-- Plain application metadata — no size limit, no crypto-suggestive name.
-- MUST NOT FIRE.
CREATE TABLE app_settings (
    id INT PRIMARY KEY,
    metadata TEXT
);
