# Intelligent Scan-Grounded Q&A Assistant

A completely local, offline, scan-grounded natural-language assistant over Hash Patch scans and migration plans. It replaces brittle regex-based category routing with a normalized scan index, query analyzer, multi-document retriever, and conversation tracking layer — backed by local Ollama (`phi3:mini`).

---

## 1. Architecture Overview

The system is organized into decoupled layers:

```
                  +-----------------------------------+
                  |        User Natural Query         |
                  +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  |     QueryAnalyzer (query.py)      |
                  | - Domain Thesaurus (ECC, etc.)    |
                  | - Intent Classification           |
                  | - Entity & Filter Extraction      |
                  | - Conversational Context Tracker  |
                  |   (Pronouns, Active Finding,      |
                  |    Pairwise Comparison Set)       |
                  +-----------------------------------+
                                    | ParsedQuery
                                    v
+------------------+      +-----------------------------------+
|  CBOM / Plan     | ---> |      ScanIndex (index.py)         |
|  Current Scan    |      | - Scan-level totals               |
+------------------+      | - Finding records & evidence      |
                          | - Repository language/dir metrics |
                          | - Relationship graph edges        |
                          | - Migration candidates & schedule |
                          | - Shelf-life & blast-radius       |
                          +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  |       Retriever (retriever.py)    |
                  | - Deterministic Python aggregates |
                  | - Multi-document context builder  |
                  | - Graph neighbor traversal        |
                  | - Source tracking & traceability  |
                  +-----------------------------------+
                                    | RetrievalResult (context + sources)
                                    v
                  +-----------------------------------+
                  |   Grounding Orchestrator          |
                  |   (grounding.py)                  |
                  | - Deterministic guardrails (CVE,  |
                  |   legal frameworks refusal)       |
                  | - Conversational pass-through     |
                  +-----------------------------------+
                                    | GroundingResult
                                    v
                  +-----------------------------------+
                  |  Ollama Client (ollama_client.py) |
                  | - Local phi3:mini (~3.8B)         |
                  | - Grounded reasoned explanations  |
                  | - Multi-turn conversation context |
                  +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  | AskResponse (service.py: /api/ask)|
                  | answer, grounded, sources, matched|
                  +-----------------------------------+
```

---

## 2. Core Principles & Safety Guardrails

1. **Strict Grounding in the Current Scan**:
   - The assistant answers only from facts in the active CBOM and migration plan.
   - It **never invents** CVEs, key sizes, external compliance frameworks, or non-existent file paths.
   - **Adversarial queries** (e.g. asking for CVEs or GDPR compliance) are deterministically rejected without LLM invocation.

2. **Reasoned Synthesis vs. Invention**:
   - "Grounded" does not mean word-for-word repetition. The model is instructed to synthesize and explain classifications (e.g., explaining why Shor-vulnerability + Live-External reachability makes an asset urgent).

3. **Deterministic Computation in Python**:
   - The LLM **never manually counts or sums records**.
   - Python computes: total findings, operation/reference splits, quantum vulnerability breakdowns, reachability totals, risk ranks, schedule sums, and blast radii.
   - The LLM receives the exact computed numbers and explains them naturally.

4. **Multi-Document Evidence & Traceability**:
   - Every answer tracks which scan records support it via `sources: list[str]`, e.g.:
     `["report:scan_summary", "finding:ECDSA:.../PaymentSigner.java", "migration:candidate:Ed25519"]`.

5. **Conversational Context & Pronoun Resolution**:
   - Tracks `active_findings`, `comparison_findings`, `last_intent`, and `last_question`.
   - Resolves references like `"is it live?"`, `"where is it used?"`, and entity switches like `"what about ECDSA?" -> "which one is worse?"`.

---

## 3. Supported Natural Language Capabilities

- **General Scan Overview**: `"findings?"`, `"what's going on here?"`, `"what did you find?"`, `"show me what's wrong"`, `"anything serious?"`, `"give me the big picture"`
- **Finding Lookups & Thesaurus**: `"tell me about RSA"`, `"what about the ECC stuff?"`, `"show me the old hashes"`, `"what did the scan find in Java?"`, `"show me everything about RSA"`
- **Why Flagged**: `"why is RSA bad?"`, `"why should I care about Ed25519?"`
- **Reachability**: `"what is actually live?"`, `"what is exposed externally?"`, `"do we have dead crypto?"`, `"how much is unresolved?"`
- **Relationships & Blast Radius**: `"what depends on RSA?"`, `"what will this affect?"`, `"what breaks if I migrate Ed25519?"`
- **Migration & Ordering**: `"what should I fix first and why?"`, `"what's the migration order?"`, `"how much effort is involved?"`, `"which migration gives the biggest risk reduction?"`
- **Comparison**: `"compare RSA and ECDSA"`, `"which is worse, RSA or ECDSA?"`, `"RSA vs ECDSA"`
- **Report & Executive Numbers**: `"what does the report say?"`, `"give me the executive summary"`, `"how many files were scanned?"`, `"what is the longest shelf life?"`
- **Conversational Follow-ups**:
  - `User`: "Tell me about RSA."
  - `User`: "Is it live?" (Resolves "it" to RSA)
  - `User`: "Where is it used?" (Retrieves RSA locators)
  - `User`: "What about ECDSA?" (Switches active entity to ECDSA)
  - `User`: "Which one is worse?" (Compares RSA and ECDSA)
- **Out of Scope & Refusals**: `"what is the weather today?"`, `"write me a poem"` (gracefully refused as out-of-scope without hallucination).

---

## 4. Local Execution & Model Choice

- **Default Model**: `phi3:mini` (Microsoft, ~3.8B parameters) via Ollama (`http://localhost:11434`).
- **No Cloud Dependencies**: Zero external API calls, zero telemetry, fully offline.
- **Latency**: Sub-millisecond indexation and retrieval; ~3–6s Ollama inference generation on standard local hardware.
