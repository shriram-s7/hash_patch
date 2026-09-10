"""tests/unit/test_data_chain.py

Unit tests for hash_patch/analyze/data_chain.py — same-function data-flow
chain edges (Java only), a relationship type explicitly distinct from the
cross-function call-graph edges in hash_patch/analyze/call_relations.py.

Runs the real CLI scan path (hash_patch.cli.run_scan) over
testdata/java/data_chain/ and asserts on the `hash_patch:property.dataChain`
value attached to each finding, so the edges are regression-tested against
the real property shape the emitted CBOM carries, not just the in-memory
dict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hash_patch.cli import run_scan
from hash_patch.model.assets import CryptoAsset

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_JAVA_DATA_CHAIN_DIR = REPO_ROOT / "testdata" / "java" / "data_chain"
CBOM_CRYPTO_TEST_DIR = REPO_ROOT / "testdata" / "java" / "cbom_crypto_test"
if not CBOM_CRYPTO_TEST_DIR.is_dir():
    CBOM_CRYPTO_TEST_DIR = REPO_ROOT.parent / "cbom_crypto_test"


def _asset_at_line(assets: list[CryptoAsset], locator_suffix: str, line: int) -> CryptoAsset | None:
    for asset in assets:
        for ev in asset.evidence:
            if ev.locator.replace("\\", "/").endswith(locator_suffix) and ev.line == line:
                return asset
    return None


def _data_chain(asset: CryptoAsset) -> dict[str, Any] | None:
    raw = asset.properties.get("dataChain")
    if raw is None:
        return None
    return json.loads(raw)


def test_cascade_chains_rsa_cipher_to_aes_cipher_to_chacha_cipher() -> None:
    """Main.java: rsaCipher's ciphertext is nested directly as aesCipher's
    argument (case a), and aesCipher's ciphertext is passed via a bare local
    variable to chaChaCipher (case b). Both must produce a
    same_function_data_chain edge, in the right direction and between the
    right pair of findings.
    """
    result = run_scan(TESTDATA_JAVA_DATA_CHAIN_DIR)

    rsa_kpg = _asset_at_line(result.assets, "Main.java", 25)
    rsa_cipher = _asset_at_line(result.assets, "Main.java", 26)
    aes_kg = _asset_at_line(result.assets, "Main.java", 28)
    aes_cipher = _asset_at_line(result.assets, "Main.java", 29)
    chacha_kg = _asset_at_line(result.assets, "Main.java", 33)
    chacha_cipher = _asset_at_line(result.assets, "Main.java", 34)

    assert rsa_kpg is not None, "RSA KeyPairGenerator.getInstance finding not found"
    assert rsa_cipher is not None, "RSA Cipher.getInstance finding not found"
    assert aes_kg is not None, "AES KeyGenerator.getInstance finding not found"
    assert aes_cipher is not None, "AES-GCM Cipher.getInstance finding not found"
    assert chacha_kg is not None, "ChaCha20 KeyGenerator.getInstance finding not found"
    assert chacha_cipher is not None, "ChaCha20-Poly1305 Cipher.getInstance finding not found"

    rsa_chain = _data_chain(rsa_cipher)
    assert rsa_chain is not None, "RSA cipher finding should carry a hash_patch:property.dataChain"
    assert rsa_chain["chainTargets"] == [aes_cipher.id]
    assert rsa_chain["chainSources"] == []

    aes_chain = _data_chain(aes_cipher)
    assert aes_chain is not None, "AES-GCM cipher finding should carry a hash_patch:property.dataChain"
    assert aes_chain["chainSources"] == [rsa_cipher.id]
    assert aes_chain["chainTargets"] == [chacha_cipher.id]

    chacha_chain = _data_chain(chacha_cipher)
    assert chacha_chain is not None, "ChaCha20-Poly1305 cipher finding should carry a hash_patch:property.dataChain"
    assert chacha_chain["chainSources"] == [aes_cipher.id]
    assert chacha_chain["chainTargets"] == []

    # The three keygen findings are never used as an argument to anything in
    # Main.java -- they must stay isolated: no dataChain property at all.
    for keygen_asset in (rsa_kpg, aes_kg, chacha_kg):
        assert _data_chain(keygen_asset) is None


def test_unrelated_same_function_hashes_produce_no_chain_edge() -> None:
    """NegativeUnrelatedHashes.java: two hash calls in the same method, each
    over its own independent input. No data flows between them, so neither
    finding may carry a dataChain edge pointing at the other.
    """
    result = run_scan(TESTDATA_JAVA_DATA_CHAIN_DIR)

    sha256 = _asset_at_line(result.assets, "NegativeUnrelatedHashes.java", 19)
    sha3 = _asset_at_line(result.assets, "NegativeUnrelatedHashes.java", 22)
    assert sha256 is not None, "SHA-256 finding not found in NegativeUnrelatedHashes.java"
    assert sha3 is not None, "SHA3-256 finding not found in NegativeUnrelatedHashes.java"

    sha256_chain = _data_chain(sha256)
    if sha256_chain is not None:
        assert sha3.id not in sha256_chain["chainTargets"]
        assert sha3.id not in sha256_chain["chainSources"]

    sha3_chain = _data_chain(sha3)
    if sha3_chain is not None:
        assert sha256.id not in sha3_chain["chainTargets"]
        assert sha256.id not in sha3_chain["chainSources"]


def test_keygen_to_cipher_key_material_binding(tmp_path: Path) -> None:
    """KeyGenerator produces SecretKey via generateKey(), which is passed
    to Cipher.init(mode, key). This must produce a directed data_chain edge:
    keygen -> cipher.
    """
    java_file = tmp_path / "KeyMaterialBinding.java"
    java_file.write_text(
        """package com.example.datachain;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyMaterialBinding {
    public static void testKeyBinding() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        cipher.doFinal("hello".getBytes());
    }
}
""",
        encoding="utf-8",
    )
    result = run_scan(tmp_path)

    kg = _asset_at_line(result.assets, "KeyMaterialBinding.java", 8)
    cipher = _asset_at_line(result.assets, "KeyMaterialBinding.java", 11)

    assert kg is not None, "KeyGenerator finding not found in KeyMaterialBinding.java"
    assert cipher is not None, "Cipher finding not found in KeyMaterialBinding.java"

    kg_chain = _data_chain(kg)
    assert kg_chain is not None, "Keygen should carry dataChain property when key is used"
    assert kg_chain["chainTargets"] == [cipher.id]
    assert kg_chain["chainSources"] == []

    cipher_chain = _data_chain(cipher)
    assert cipher_chain is not None, "Cipher should carry dataChain property when initialized with key"
    assert cipher_chain["chainSources"] == [kg.id]
    assert cipher_chain["chainTargets"] == []
    assert kg_chain.get("chainType") == "key_material"
    assert any(
        e["source"] == kg.id and e["target"] == cipher.id and e["chainType"] == "key_material"
        for e in kg_chain.get("edges", [])
    )


def test_cascade_ciphertext_chain_edge_type() -> None:
    """In cbom_crypto_test/Main.java, rsaCipher's output is passed to
    aesCipher, and aesCipher's output is passed to chaChaCipher. Both edges
    must carry chainType == "ciphertext".
    """
    if not CBOM_CRYPTO_TEST_DIR.is_dir():
        pytest.skip(f"{CBOM_CRYPTO_TEST_DIR} does not exist")
    result = run_scan(CBOM_CRYPTO_TEST_DIR)

    rsa_cipher = _asset_at_line(result.assets, "Main.java", 19)
    aes_cipher = _asset_at_line(result.assets, "Main.java", 30)
    chacha_cipher = _asset_at_line(result.assets, "Main.java", 40)

    assert rsa_cipher is not None, "RSA cipher finding not found"
    assert aes_cipher is not None, "AES cipher finding not found"
    assert chacha_cipher is not None, "ChaCha20 cipher finding not found"

    # 1. RSA cipher -> AES cipher edge
    rsa_chain = _data_chain(rsa_cipher)
    assert rsa_chain is not None
    rsa_to_aes_edges = [
        e for e in rsa_chain.get("edges", [])
        if e["source"] == rsa_cipher.id and e["target"] == aes_cipher.id
    ]
    assert len(rsa_to_aes_edges) == 1, "Expected single edge from RSA cipher to AES cipher"
    assert rsa_to_aes_edges[0]["chainType"] == "ciphertext"

    # 2. AES cipher -> ChaCha20 cipher edge
    aes_chain = _data_chain(aes_cipher)
    assert aes_chain is not None
    aes_to_chacha_edges = [
        e for e in aes_chain.get("edges", [])
        if e["source"] == aes_cipher.id and e["target"] == chacha_cipher.id
    ]
    assert len(aes_to_chacha_edges) == 1, "Expected single edge from AES cipher to ChaCha cipher"
    assert aes_to_chacha_edges[0]["chainType"] == "ciphertext"


def test_cascade_key_material_binding_edge_type() -> None:
    """In cbom_crypto_test/Main.java, each KeyGenerator / KeyPairGenerator
    passes its key to a Cipher's .init(...) call. These edges must carry
    chainType == "key_material", and pure-keygen assets should have a
    uniform chainType == "key_material".
    """
    if not CBOM_CRYPTO_TEST_DIR.is_dir():
        pytest.skip(f"{CBOM_CRYPTO_TEST_DIR} does not exist")
    result = run_scan(CBOM_CRYPTO_TEST_DIR)

    rsa_kpg = _asset_at_line(result.assets, "Main.java", 15)
    rsa_cipher = _asset_at_line(result.assets, "Main.java", 19)
    aes_kg = _asset_at_line(result.assets, "Main.java", 23)
    aes_cipher = _asset_at_line(result.assets, "Main.java", 30)
    chacha_kg = _asset_at_line(result.assets, "Main.java", 34)
    chacha_cipher = _asset_at_line(result.assets, "Main.java", 40)
    blowfish_kg = _asset_at_line(result.assets, "Main.java", 50)
    blowfish_cipher = _asset_at_line(result.assets, "Main.java", 54)

    assert rsa_kpg is not None
    assert rsa_cipher is not None
    assert aes_kg is not None
    assert aes_cipher is not None
    assert chacha_kg is not None
    assert chacha_cipher is not None
    assert blowfish_kg is not None
    assert blowfish_cipher is not None

    # Check RSA KeyPairGenerator -> RSA Cipher binding
    rsa_kpg_chain = _data_chain(rsa_kpg)
    assert rsa_kpg_chain is not None
    assert rsa_kpg_chain.get("chainType") == "key_material"
    rsa_kpg_edges = [
        e for e in rsa_kpg_chain.get("edges", [])
        if e["source"] == rsa_kpg.id and e["target"] == rsa_cipher.id
    ]
    assert len(rsa_kpg_edges) == 1
    assert rsa_kpg_edges[0]["chainType"] == "key_material"

    # Check AES KeyGenerator -> AES Cipher binding
    aes_kg_chain = _data_chain(aes_kg)
    assert aes_kg_chain is not None
    assert aes_kg_chain.get("chainType") == "key_material"
    aes_kg_edges = [
        e for e in aes_kg_chain.get("edges", [])
        if e["source"] == aes_kg.id and e["target"] == aes_cipher.id
    ]
    assert len(aes_kg_edges) == 1
    assert aes_kg_edges[0]["chainType"] == "key_material"

    # Check ChaCha KeyGenerator -> ChaCha Cipher binding
    chacha_kg_chain = _data_chain(chacha_kg)
    assert chacha_kg_chain is not None
    assert chacha_kg_chain.get("chainType") == "key_material"
    chacha_kg_edges = [
        e for e in chacha_kg_chain.get("edges", [])
        if e["source"] == chacha_kg.id and e["target"] == chacha_cipher.id
    ]
    assert len(chacha_kg_edges) == 1
    assert chacha_kg_edges[0]["chainType"] == "key_material"

    # Check Blowfish KeyGenerator -> Blowfish Cipher binding
    bf_kg_chain = _data_chain(blowfish_kg)
    assert bf_kg_chain is not None
    assert bf_kg_chain.get("chainType") == "key_material"
    bf_kg_edges = [
        e for e in bf_kg_chain.get("edges", [])
        if e["source"] == blowfish_kg.id and e["target"] == blowfish_cipher.id
    ]
    assert len(bf_kg_edges) == 1
    assert bf_kg_edges[0]["chainType"] == "key_material"


