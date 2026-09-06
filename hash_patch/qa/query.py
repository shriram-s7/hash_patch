"""hash_patch/qa/query.py — Query understanding, conservative entity resolution,
domain thesaurus, and conversational state tracking.

Translates natural English into a precise NormalizedQuery for deterministic retrieval.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Domain thesaurus: canonical crypto concepts, variants, and entity families
CRYPTO_THESAURUS: dict[str, list[str]] = {
    # Elliptic curve variants and families (conservative: no bare "ec")
    "ecc": ["ECDSA", "ECDH"],
    "ec signature": ["ECDSA"],
    "ec signatures": ["ECDSA"],
    "elliptic curve signing": ["ECDSA"],
    "elliptic-curve signing": ["ECDSA"],
    "elliptic curve signature": ["ECDSA"],
    "elliptic-curve signature": ["ECDSA"],
    "elliptic curve key exchange": ["ECDH"],
    "elliptic-curve key exchange": ["ECDH"],
    "elliptic curve crypto": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "elliptic curve cryptography": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "elliptic curve algorithms": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "all ec crypto": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "all ec": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "ec crypto": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "elliptic curve": ["ECDSA", "ECDH", "Ed25519", "X25519"],
    "ecdsa": ["ECDSA"],
    "ecdh": ["ECDH"],

    # RSA variants and families
    "rsa": ["RSA", "RSASSA-PSS", "RSASSA-PKCS1v15", "RSA-OAEP"],
    "rsa crypto": ["RSA"],
    "rsa stuff": ["RSA"],
    "all rsa": ["RSA", "RSASSA-PSS", "RSASSA-PKCS1v15", "RSA-OAEP"],
    "all rsa stuff": ["RSA", "RSASSA-PSS", "RSASSA-PKCS1v15", "RSA-OAEP"],
    "rsassa-pss": ["RSASSA-PSS", "RSA"],
    "rsa-oaep": ["RSA-OAEP", "RSA"],

    # AES variants and families
    "aes": ["AES", "AES-GCM", "AES-CBC"],
    "aes-gcm": ["AES-GCM", "AES"],
    "aes gcm": ["AES-GCM", "AES"],
    "aes-cbc": ["AES-CBC", "AES"],
    "aes cbc": ["AES-CBC", "AES"],
    "all aes": ["AES", "AES-GCM", "AES-CBC"],

    # Discrete log / Diffie-Hellman / DSA
    "dsa": ["DSA"],
    "dh": ["DH", "Diffie-Hellman"],
    "diffie-hellman": ["DH"],
    "diffie hellman": ["DH"],

    # Edwards / Montgomery curves
    "ed25519": ["Ed25519"],
    "ed-25519": ["Ed25519"],
    "ed 25519": ["Ed25519"],
    "x25519": ["X25519"],
    "x-25519": ["X25519"],

    # Legacy ciphers
    "rc4": ["RC4", "RC4-SHA"],
    "rc4-sha": ["RC4-SHA", "RC4"],
    "des": ["DES", "3DES"],
    "3des": ["3DES"],
    "triple des": ["3DES"],

    # Hashes and hash families
    "sha1": ["SHA-1"],
    "sha-1": ["SHA-1"],
    "sha 1": ["SHA-1"],
    "sha256": ["SHA-256"],
    "sha-256": ["SHA-256"],
    "sha 256": ["SHA-256"],
    "sha384": ["SHA-384"],
    "sha-384": ["SHA-384"],
    "sha512": ["SHA-512"],
    "sha-512": ["SHA-512"],
    "md5": ["MD5"],
    "hash algorithms": ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5"],
    "all hashes": ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5"],
    "hash functions": ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5"],
    "hashes": ["SHA-1", "SHA-256", "MD5"],
    "old hashes": ["SHA-1", "MD5"],
    "weak hashes": ["SHA-1", "MD5"],

    # Post-Quantum and negative-test algorithms
    "ml-kem": ["ML-KEM-768", "ML-KEM"],
    "ml-kem-768": ["ML-KEM-768"],
    "ml-dsa": ["ML-DSA-65", "ML-DSA"],
    "ml-dsa-65": ["ML-DSA-65"],
    "kyber": ["Kyber"],
    "dilithium": ["Dilithium"],
    "blowfish": ["Blowfish"],
    "chacha20": ["ChaCha20"],
    "elgamal": ["ElGamal"],
    "twofish": ["Twofish"],
    "pqc": ["ML-KEM-768", "ML-DSA-65"],
    "post-quantum": ["ML-KEM-768", "ML-DSA-65"],
    "post quantum": ["ML-KEM-768", "ML-DSA-65"],

    # Broad conceptual families
    "asymmetric": ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "X25519"],
    "public key": ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "X25519"],
    "public-key": ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "X25519"],
    "public key crypto": ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "X25519"],
    "public-key crypto": ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "X25519"],
    "signature algorithms": ["RSA", "ECDSA", "Ed25519", "DSA", "ML-DSA-65"],
    "signatures": ["RSA", "ECDSA", "Ed25519", "DSA", "ML-DSA-65"],
    "broken signatures": ["RSA", "ECDSA", "DSA"],
    "symmetric": ["AES", "3DES", "DES", "RC4", "ChaCha20"],
    "ciphers": ["AES", "3DES", "DES", "RC4", "ChaCha20"],
}

# Known ungroundable concepts
CVE_PATTERN = re.compile(r"\bcve\b", re.IGNORECASE)
LEGAL_FRAMEWORK_PATTERN = re.compile(
    r"\b(gdpr|hipaa|pci[\s-]?dss|sox|ccpa|iso\s?27001|nist\s?800|fedramp)\b", re.IGNORECASE
)

# Out of scope questions (unrelated to scan/codebase)
OUT_OF_SCOPE_PATTERNS = [
    re.compile(r"\b(meaning of life|write (me )?a (python )?(web server|script|poem|song|story)|weather|bitcoin|stock price|cricket|joke|recipe)\b", re.IGNORECASE),
    re.compile(r"\b(who (is|are) you|who made you|how are you|how old are you)\b", re.IGNORECASE),
]

# Greetings and conversational phrases
GREETING_WORDS = frozenset(
    {
        "hi", "hello", "hey", "yo", "sup", "howdy", "greetings",
        "thanks", "thank you", "thx", "ty", "cheers",
        "ok", "okay", "cool", "nice", "great",
        "good morning", "good afternoon", "good evening",
        "bye", "goodbye", "see you", "whats up", "what's up",
    }
)
GREETING_START = re.compile(
    r"^(hi|hello|hey|yo|howdy|greetings|thanks|thank you|thx|ty|cheers|bye|goodbye)\b",
    re.IGNORECASE,
)


@dataclass
class ConversationContext:
    scan_id: str | None = None
    last_question: str | None = None
    last_answer: str | None = None
    active_findings: list[str] = field(default_factory=list)  # e.g. ["RSA"]
    comparison_findings: list[str] = field(default_factory=list)  # e.g. ["RSA", "ECDSA"]
    last_intent: str | None = None

    def update(self, question: str, answer: str, parsed: NormalizedQuery) -> None:
        self.last_question = question
        self.last_answer = answer
        self.last_intent = parsed.intent
        if parsed.entities:
            if parsed.is_comparison and len(parsed.entities) >= 2:
                self.comparison_findings = list(parsed.entities[:2])
                self.active_findings = list(parsed.entities[:1])
            else:
                prev_active = list(self.active_findings)
                self.active_findings = list(parsed.entities)
                if len(parsed.entities) == 1:
                    new_ent = parsed.entities[0]
                    if prev_active and prev_active[0].upper() != new_ent.upper():
                        self.comparison_findings = [prev_active[0], new_ent]
                    elif not self.comparison_findings:
                        self.comparison_findings = [new_ent]


@dataclass
class NormalizedQuery:
    """Structured internal query representation."""

    raw_query: str
    intent: str
    entities: list[str] = field(default_factory=list)
    unresolved_entities: list[str] = field(default_factory=list)
    reachability_filter: str | None = None
    quantum_filter: str | None = None
    finding_type_filter: str | None = None
    language_filter: str | None = None
    sensitivity_category: str | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    scope: str = "all"
    aggregation_type: str | None = None
    relationship_direction: str | None = None
    ranking: str | None = None
    limit: int = 10
    is_comparison: bool = False
    comparison_targets: list[str] = field(default_factory=list)
    is_conversational: bool = False
    is_out_of_scope: bool = False
    ungroundable_reason: str | None = None
    needs_relationships: bool = False
    needs_migration: bool = False
    needs_report: bool = False
    is_aggregation: bool = False
    is_why: bool = False
    required_pillars: set[str] = field(default_factory=set)
    is_cross_pillar: bool = False
    is_multi_hop: bool = False


# Backward-compatible alias
ParsedQuery = NormalizedQuery


class QueryAnalyzer:
    """Analyzes a natural language question against known scan entities and conversation state."""

    @classmethod
    def parse(
        cls,
        question: str,
        known_component_names: set[str],
        conversation: ConversationContext | None = None,
        scan_id: str | None = None,
    ) -> NormalizedQuery:
        trimmed = question.strip()
        lowered = trimmed.lower()

        # Enforce strict scan isolation on conversation state
        if conversation and conversation.scan_id and scan_id and conversation.scan_id != scan_id:
            conversation = None

        # 1. Conversational pass-through
        if cls._is_conversational(trimmed):
            return NormalizedQuery(
                raw_query=trimmed,
                intent="CONVERSATIONAL",
                is_conversational=True,
            )

        # 2. Known ungroundable (deterministic safety boundary)
        ungroundable = cls._check_ungroundable(trimmed)
        if ungroundable:
            return NormalizedQuery(
                raw_query=trimmed,
                intent="KNOWN_UNGROUNDABLE",
                ungroundable_reason=ungroundable,
            )

        # 3. Out-of-scope queries (general trivia, poems, unrelated topics)
        if cls._is_out_of_scope(trimmed):
            return NormalizedQuery(
                raw_query=trimmed,
                intent="OUT_OF_SCOPE",
                is_out_of_scope=True,
            )

        # 4. Extract entities & resolve pronouns
        entities, unresolved_entities = cls._extract_entities(lowered, known_component_names)

        # Pronoun and coreference resolution using conversation context
        if not entities and conversation and conversation.active_findings:
            if re.search(r"\b(it|its|it's|this|that|these|the algorithm|this crypto|the finding|this one)\b", lowered) or re.search(r"^(is it |who calls |what calls |where is it |what happens if |what breaks if |what depends on |what about its )", lowered):
                entities = list(conversation.active_findings)

        # Check for comparison
        is_comparison = False
        comparison_targets: list[str] = []
        is_comp_phrase = bool(
            re.search(
                r"\b(compare|versus|\bvs\b|difference between|which (one )?is (worse|better|safer|more exposed|higher risk)|"
                r"which (one )?should i (fix|migrate)|which has the (bigger|larger) blast radius)\b",
                lowered,
            )
            or (" and " in lowered and len(entities) >= 2)
            or (" vs " in lowered)
        )
        if is_comp_phrase:
            if len(entities) >= 2:
                is_comparison = True
                comparison_targets = list(entities)
            elif conversation and len(entities) == 1 and conversation.active_findings:
                first = conversation.active_findings[0]
                second = entities[0]
                if first.upper() != second.upper():
                    is_comparison = True
                    comparison_targets = [first, second]
                    entities = [first, second]
            elif conversation and len(entities) == 0 and conversation.comparison_findings:
                is_comparison = True
                comparison_targets = list(conversation.comparison_findings)
                entities = list(conversation.comparison_findings)

        # 5. Extract filters
        reachability_filter = cls._extract_reachability_filter(lowered)
        quantum_filter = cls._extract_quantum_filter(lowered)
        finding_type_filter = cls._extract_finding_type_filter(lowered)
        language_filter = cls._extract_language_filter(lowered)
        sensitivity_category = cls._extract_sensitivity_category(lowered)

        filters: dict[str, Any] = {}
        if reachability_filter:
            filters["reachability"] = reachability_filter
        if quantum_filter:
            filters["quantum_status"] = quantum_filter
        if finding_type_filter:
            filters["finding_type"] = finding_type_filter
        if language_filter:
            filters["language"] = language_filter
        if sensitivity_category:
            filters["sensitivity_category"] = sensitivity_category

        # 6. Detect Intent & Aggregation Type
        intent, aggregation_type, ranking, scope = cls._classify_intent(
            lowered,
            entities=entities,
            unresolved=unresolved_entities,
            conversation=conversation,
            is_comparison=is_comparison,
            reachability_filter=reachability_filter,
            quantum_filter=quantum_filter,
            finding_type_filter=finding_type_filter,
            language_filter=language_filter,
            sensitivity_category=sensitivity_category,
        )

        # 7. Required pillars detection
        required_pillars: set[str] = set()
        if quantum_filter or re.search(
            r"\b(shor|grover|classically|quantum|vulnerable|broken|dangerous|unsafe|insecure|scary)\b",
            lowered,
        ):
            required_pillars.add("VULNERABILITY")

        if reachability_filter or re.search(
            r"\b(external|externally|exposed|internet|live|network|internal|inert|dead|uncalled|unreachable|production|reachable|reachability)\b",
            lowered,
        ):
            required_pillars.add("REACHABILITY")

        if re.search(
            r"\b(migrate|migration|fix first|start with|priority|prioritize|schedule|budget|cost|effort|hardest to migrate)\b",
            lowered,
        ):
            required_pillars.add("MIGRATION")

        if re.search(
            r"\b(blast[- ]?radius|break|overflow|buffer|stack[- ]?buffer|heap[- ]?buffer|replace|replacing|replacement)\b",
            lowered,
        ):
            required_pillars.add("BLAST_RADIUS")

        if sensitivity_category or re.search(
            r"\b(sensitive|shelf[- ]?life|retention|mosca|statutory|dpdp|pan|financial|health|biometric|patient|confidentiality)\b",
            lowered,
        ):
            required_pillars.add("SENSITIVE_DATA")

        if re.search(
            r"\b(depend|depends|dependency|dependencies|call|caller|callee|calling|calls|called|graph|edge|downstream|upstream|multi[- ]?hop|transitively|ultimately)\b",
            lowered,
        ):
            required_pillars.add("RELATIONSHIPS")

        if re.search(
            r"\b(contradiction|contradictions|divergence|inconsistent|inconsistency|policy|violat(e|ion|ing)|declared vs|implemented vs)\b",
            lowered,
        ):
            required_pillars.add("CONTRADICTIONS")

        if finding_type_filter == "CRYPTO_REFERENCE" or re.search(
            r"\b(reference|references|only mentioned|comment|string literal|fixture)\b",
            lowered,
        ):
            required_pillars.add("REFERENCES")

        if re.search(
            r"\b(deployment|topology|iac|kubernetes|terraform|workload|service|ingress|loadbalancer|load-balancer|namespace|externally exposed|exposed externally|internet facing|internet-facing|publicly exposed|clusterip|nodeport|mixed exposure|exposure|mixed|unknown exposure)\b",
            lowered,
        ):
            required_pillars.add("IAC_EXPOSURE")

        if entities or re.search(r"\b(finding|findings|asset|assets|algorithm|algorithms|show me|tell me|what did you find)\b", lowered):
            required_pillars.add("FINDINGS")

        # Multi-hop detection
        is_multi_hop = bool(
            re.search(
                r"\b(ultimately|eventually|multi[- ]?hop|call chain|call path|transitive|transitively|downstream path)\b",
                lowered,
            )
        )

        # Cross-pillar compound query detection
        is_deep_entity = bool(
            entities
            and re.search(
                r"\b(everything important|full impact|deep dive|all about|complete picture|all details)\b",
                lowered,
            )
        )

        operational_pillars = required_pillars & {
            "VULNERABILITY",
            "REACHABILITY",
            "MIGRATION",
            "BLAST_RADIUS",
            "SENSITIVE_DATA",
            "RELATIONSHIPS",
            "CONTRADICTIONS",
            "IAC_EXPOSURE",
        }

        # Compound cross-pillar queries combine 2+ operational pillars or deep entity/multi-hop
        is_compound = (
            ("VULNERABILITY" in operational_pillars and "REACHABILITY" in operational_pillars)
            or ("VULNERABILITY" in operational_pillars and "MIGRATION" in operational_pillars)
            or ("REACHABILITY" in operational_pillars and "MIGRATION" in operational_pillars)
            or ("SENSITIVE_DATA" in operational_pillars and "VULNERABILITY" in operational_pillars)
            or ("REACHABILITY" in operational_pillars and "RELATIONSHIPS" in operational_pillars)
            or ("MIGRATION" in operational_pillars and "BLAST_RADIUS" in operational_pillars)
            or ("CONTRADICTIONS" in operational_pillars and ("REACHABILITY" in operational_pillars or "FINDINGS" in required_pillars))
            or is_deep_entity
            or (is_multi_hop and "RELATIONSHIPS" in operational_pillars)
        )

        is_cross_pillar = is_compound and not is_comparison and intent not in ("OVERVIEW", "KNOWN_UNGROUNDABLE", "OUT_OF_SCOPE", "CONVERSATIONAL", "GLOSSARY")

        if is_cross_pillar:
            intent = "CROSS_PILLAR"
            if ranking is None:
                if re.search(r"\b(fix first|migrate first|first|priority|prioritize|most dangerous|worst)\b", lowered):
                    ranking = "risk"
                elif re.search(r"\b(most downstream|most dependencies|most callers)\b", lowered):
                    ranking = "dependencies"

        is_why = intent == "WHY_FLAGGED" or re.search(r"\bwhy\b", lowered) is not None
        is_aggregation = aggregation_type is not None or bool(
            re.search(r"\b(how many|count|distribution|number of|percentage|most often)\b", lowered)
        )
        needs_relationships = intent == "RELATIONSHIPS" or bool(
            re.search(r"\b(depend|connected|call|caller|callee|affect|impact|blast radius)\b", lowered)
        )
        needs_migration = intent in ("MIGRATION", "COMPARISON") or bool(
            re.search(r"\b(migrate|migration|fix first|budget|effort|order|schedule)\b", lowered)
        )
        needs_report = intent == "REPORT" or bool(
            re.search(r"\b(report|executive summary|files scanned|how many files|contradiction|limitation|unknowns)\b", lowered)
        )

        relationship_direction = None
        if needs_relationships:
            if re.search(r"\b(caller|who calls|what calls|who called|called from|incoming)\b", lowered):
                relationship_direction = "callers"
            elif re.search(r"\b(callee|what does it call|outgoing)\b", lowered):
                relationship_direction = "callees"
            else:
                relationship_direction = "both"

        return NormalizedQuery(
            raw_query=trimmed,
            intent=intent,
            entities=entities,
            unresolved_entities=unresolved_entities,
            reachability_filter=reachability_filter,
            quantum_filter=quantum_filter,
            finding_type_filter=finding_type_filter,
            language_filter=language_filter,
            sensitivity_category=sensitivity_category,
            filters=filters,
            scope=scope,
            aggregation_type=aggregation_type,
            relationship_direction=relationship_direction,
            ranking=ranking,
            limit=10,
            is_comparison=is_comparison,
            comparison_targets=comparison_targets,
            needs_relationships=needs_relationships,
            needs_migration=needs_migration,
            needs_report=needs_report,
            is_aggregation=is_aggregation,
            is_why=is_why,
            required_pillars=required_pillars,
            is_cross_pillar=is_cross_pillar,
            is_multi_hop=is_multi_hop,
        )

    # -------------------------------------------------------------------------
    # Helper extractors
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_conversational(text: str) -> bool:
        stripped = re.sub(r"[!?.,;:]+$", "", text.strip().lower()).strip()
        if not stripped:
            return True
        if stripped in GREETING_WORDS:
            return True
        word_count = len(stripped.split())
        return word_count <= 4 and bool(GREETING_START.match(stripped)) and "?" not in text

    @staticmethod
    def _check_ungroundable(text: str) -> str | None:
        if CVE_PATTERN.search(text):
            return (
                "This scan's data contains no CVE identifiers anywhere — Hash Patch "
                "classifies algorithms by quantum-vulnerability status "
                "(broken-by-shor / broken-classically / weakened-by-grover / "
                "quantum-safe), not by CVE. It has never invented a CVE and will not start now."
            )
        if LEGAL_FRAMEWORK_PATTERN.search(text):
            return (
                "This scan's shelf-life data only ever cites DPDP Act 2023 (India), "
                "and even that is explicitly flagged as a reasonable-effort default, "
                "not a verified legal citation. No other legal/compliance framework is referenced anywhere in this system."
            )
        return None

    @staticmethod
    def _is_out_of_scope(text: str) -> bool:
        for pat in OUT_OF_SCOPE_PATTERNS:
            if pat.search(text):
                return True
        return False

    @classmethod
    def _extract_entities(
        cls, lowered: str, known_names: set[str]
    ) -> tuple[list[str], list[str]]:
        entities: list[str] = []
        unresolved: list[str] = []
        seen = set()

        # Normalized known names map: e.g. "aesgcm" -> "AES-GCM", "sha256" -> "SHA-256"
        norm_map: dict[str, str] = {}
        for name in known_names:
            norm_key = re.sub(r"[\s\-_]+", "", name.lower())
            norm_map[norm_key] = name

        # 1. Direct match against known component names
        for name in known_names:
            n_low = name.lower()
            if re.search(rf"\b{re.escape(n_low)}\b", lowered):
                if name.upper() not in seen:
                    entities.append(name)
                    seen.add(name.upper())

        # 2. Check thesaurus mapping for specific and family concepts
        for term, mapped_list in CRYPTO_THESAURUS.items():
            if re.search(rf"\b{re.escape(term)}\b", lowered):
                # Check which mapped algorithms actually exist in this scan
                matching_in_scan = [m for m in mapped_list if m.upper() in {k.upper() for k in known_names}]
                if matching_in_scan:
                    for item in matching_in_scan:
                        if item.upper() not in seen:
                            entities.append(item)
                            seen.add(item.upper())
                else:
                    for item in mapped_list:
                        if item.upper() not in seen and item.upper() not in {k.upper() for k in known_names}:
                            unresolved.append(item)
                            seen.add(item.upper())

        # 3. Strip spaces/hyphens variant matching (e.g. "AES GCM" -> "AES-GCM", "SHA 256" -> "SHA-256")
        if not entities:
            clean_query = re.sub(r"[\s\-_]+", " ", lowered)
            words = clean_query.split()
            # Check single words
            for word in words:
                norm_word = re.sub(r"[\s\-_]+", "", word)
                if norm_word in norm_map:
                    matched_name = norm_map[norm_word]
                    if matched_name.upper() not in seen:
                        entities.append(matched_name)
                        seen.add(matched_name.upper())
            # Check two-word pairs (e.g. "sha 256", "aes gcm", "ed 25519")
            for i in range(len(words) - 1):
                norm_pair = re.sub(r"[\s\-_]+", "", f"{words[i]}{words[i+1]}")
                if norm_pair in norm_map:
                    matched_name = norm_map[norm_pair]
                    if matched_name.upper() not in seen:
                        entities.append(matched_name)
                        seen.add(matched_name.upper())

        return entities, unresolved

    @staticmethod
    def _extract_reachability_filter(lowered: str) -> str | None:
        if re.search(r"\b(live external|live-external|externally reachable|exposed externally|outside world|external crypto|publicly exposed|internet-facing|exposed to the outside|exposed to outside)\b", lowered):
            return "live-external"
        if re.search(r"\b(live internal|live-internal|internal crypto|internal only|inside only|not externally reachable|\binternal\b)\b", lowered):
            if "live-external" not in lowered and "externally" not in lowered:
                return "live-internal"
        if re.search(r"\b(inert|dead code|dead crypto|unreachable|not used|not reachable|never called|what crypto is dead|what is dead|unused|not actually used|just sitting there|\bdead\b)\b", lowered):
            return "inert"
        if re.search(r"\b(actually live|live crypto|what crypto is live|what is live|running|actually used|actually being used|what executes|what is in production)\b", lowered):
            return "live"
        if re.search(r"\b(unknown reachability|unverified reachability)\b", lowered):
            return "unknown"
        return None

    @staticmethod
    def _extract_quantum_filter(lowered: str) -> str | None:
        if re.search(r"\b(broken classically|broken-classically|classically broken|obsolete|deprecated|already broken|what is already broken)\b", lowered):
            return "broken-classically"
        if re.search(
            r"\b(broken by shor|broken-by-shor|shor|vulnerable to shor|quantum vulnerable|"
            r"quantum broken|future quantum problem|bad crypto|scary stuff|serious|"
            r"what is broken by quantum|what is broken by shor)\b",
            lowered,
        ):
            return "broken-by-shor"
        if re.search(r"\b(weakened by grover|weakened-by-grover|grover)\b", lowered):
            return "weakened-by-grover"
        if re.search(r"\b(quantum safe|quantum-safe|survives quantum|survive quantum|quantum resistant|pqc|post quantum)\b", lowered):
            return "quantum-safe"
        return None

    @staticmethod
    def _extract_finding_type_filter(lowered: str) -> str | None:
        if re.search(r"\b(crypto_reference|crypto reference|reference only|references|just a reference|string reference|only mentioned)\b", lowered):
            return "CRYPTO_REFERENCE"
        if re.search(r"\b(real operation|operation|real crypto|actual call)\b", lowered):
            return "OPERATION"
        if re.search(r"\b(binary|binaries|compiled artifact|compiled artifacts|compiled binary|compiled binaries|compiled crypto|binary crypto)\b", lowered):
            return "COMPILED_CRYPTO_ARTEFACT"
        return None

    @staticmethod
    def _extract_language_filter(lowered: str) -> str | None:
        if re.search(r"\b(python|py)\b", lowered):
            return "python"
        if re.search(r"\b(java)\b", lowered):
            return "java"
        if re.search(r"\b(golang|go)\b", lowered):
            return "go"
        if re.search(r"\b(c|c\+\+|cpp)\b", lowered):
            return "c"
        if re.search(r"\b(sql)\b", lowered):
            return "sql"
        if re.search(r"\b(binary|binaries|compiled|elf|pe|mach-o|macho)\b", lowered):
            return "binary"
        return None

    @staticmethod
    def _extract_sensitivity_category(lowered: str) -> str | None:
        if re.search(r"\b(financial|payment|credit card|pci|transaction|pan)\b", lowered):
            return "financial"
        if re.search(r"\b(biometric|face|fingerprint)\b", lowered):
            return "biometric"
        if re.search(r"\b(health|medical|patient)\b", lowered):
            return "health_record"
        if re.search(r"\b(auth|password|credential|session)\b", lowered):
            return "auth_credentials"
        return None

    @classmethod
    def _classify_intent(
        cls,
        lowered: str,
        entities: list[str],
        unresolved: list[str],
        conversation: ConversationContext | None,
        is_comparison: bool,
        reachability_filter: str | None,
        quantum_filter: str | None,
        finding_type_filter: str | None,
        language_filter: str | None,
        sensitivity_category: str | None,
    ) -> tuple[str, str | None, str | None, str]:
        """Classify intent, aggregation_type, ranking, and scope."""
        # 1. Comparison
        if is_comparison:
            ranking = "risk" if ("first" in lowered or "worse" in lowered) else None
            return "COMPARISON", "comparison", ranking, "comparison"

        # 2. Glossary / definitions
        if re.search(r"crypto_reference|crypto reference|(\breference\b.{0,30}\boperation\b)|(\boperation\b.{0,30}\breference\b)", lowered) and not re.search(r"\b(how many|show me|list|are there any|any .* references|where is .* only mentioned)\b", lowered):
            return "GLOSSARY", None, None, "glossary"

        # 3. Risk-oriented overview
        if re.search(r"\b(bad stuff|dangerous crypto|things i should worry about)\b", lowered):
            return "OVERVIEW", None, "risk", "all"

        # 4. Why flagged / how risky / why is it a problem
        if re.search(r"\b(why is|why are|why was|reason for|how risky is|why.*problem|what's wrong with|whats wrong with)\b", lowered) and (entities or conversation):
            return "WHY_FLAGGED", None, "risk", "entity"

        # 5. Blast Radius (Pillar 3)
        if re.search(
            r"\b(blast radius|what breaks|what will break|what gets affected|what happens if i replace|"
            r"what depends on .* chang(e|es|ing)?|buffer overflow|fixed-size buffer|buffer constraint|buffer)\b",
            lowered,
        ):
            ranking = "blast_radius" if ("biggest" in lowered or "largest" in lowered) else None
            return "BLAST_RADIUS", None, ranking, "blast_radius"

        # 6. Shelf-Life / Sensitive Data (Pillar 2)
        if sensitivity_category or re.search(
            r"\b(shelf[- ]?life|confidentiality|sensitive data|protects? (financial|biometric|data)|"
            r"longest confidentiality|longest shelf)\b",
            lowered,
        ):
            ranking = "shelf_life" if "longest" in lowered else None
            agg = "top_n" if "longest" in lowered else None
            return "SENSITIVE_DATA", agg, ranking, "sensitive_data"

        # 7. Migration & Priority (Pillar 5)
        if re.search(
            r"\b(what should i (fix|migrate)|migrate first|fix first|where should i start|"
            r"migration order|migration sequence|migration plan|migration recommend|recommend|"
            r"biggest risk|most urgent|highest priority|top priority|how much effort|budget to fix|"
            r"cost to migrate|largest migration effort|hardest to migrate|total cost|total effort)\b",
            lowered,
        ):
            ranking = "risk" if ("urgent" in lowered or "first" in lowered or "start" in lowered) else ("cost" if ("effort" in lowered or "hardest" in lowered) else None)
            return "MIGRATION", None, ranking, "migration"

        # 8. Relationships / Call Graph (Pillar 1)
        if re.search(r"\b(who calls|what calls|who called|what depends|depend on|connected to|callers?|callees?|where is .* called from|what is the call chain|call chain|entry point)\b", lowered):
            return "RELATIONSHIPS", None, None, "relationships"

        # 9. References (Explicit reference separation)
        if finding_type_filter == "CRYPTO_REFERENCE" or re.search(
            r"\b(where is .* only mentioned|only mentioned|pure reference|references rather than operations|"
            r"how many references|how many crypto references|show me (the )?references|crypto references|any .* references)\b",
            lowered,
        ):
            agg = "count" if "how many" in lowered else None
            return "REFERENCES", agg, None, "references"

        # 10. Reachability specifics
        if reachability_filter or re.search(
            r"\b(what is actually (being )?used|what crypto is live|what is live|what crypto is dead|"
            r"what is dead|what is dead code|what is unused|what is externally reachable|"
            r"what's exposed externally|what is exposed|what is internal|inside only|not externally reachable|"
            r"what is unknown|exposed to the outside|dead crypto|unreachable|what executes|what is in production)\b",
            lowered,
        ):
            # If asking about a specific entity (e.g. "is RSA live?"), route to entity lookup
            if entities and len(entities) == 1 and not re.search(r"\b(what crypto|what findings|which findings|what algorithms)\b", lowered):
                return "FINDINGS_LOOKUP", None, None, "entity"
            return "REACHABILITY", None, None, "reachability"

        # 10b. IaC / Deployment Topology Exposure queries (Phase 4)
        if re.search(
            r"\b(deployment|topology|iac|kubernetes|terraform|workload|service|ingress|loadbalancer|load-balancer|namespace|externally exposed|exposed externally|internet facing|internet-facing|publicly exposed|clusterip|nodeport|ingress controller|mixed exposure|exposure|mixed|unknown exposure)\b",
            lowered,
        ):
            return "IAC_EXPOSURE", None, None, "iac_exposure"

        # 11a. Container image crypto queries
        if re.search(
            r"\b(container|containers|docker|oci|image layer|layers?|in the image|inside the container|inside this container|this container|final image|deleted by later layers)\b",
            lowered,
        ):
            return "CONTAINER_CRYPTO", None, None, "container"

        # 11b. Binary crypto & execution queries
        if re.search(
            r"\b(binary|binaries|compiled artifact|compiled artifacts|compiled binary|compiled binaries|libcrypto|linked library|library-level|library level|algorithm string|algorithm strings|actually execute|actually executes|actually executed|runtime execution|definitely execute|definitely executed|binary scanning)\b",
            lowered,
        ):
            return "BINARY_CRYPTO", None, None, "binary"

        # 12. Quantum / Vulnerability classification
        if quantum_filter or re.search(
            r"\b(what is broken|what is broken by quantum|what is broken by shor|what is classically broken|"
            r"what is weakened by grover|what survives quantum|"
            r"quantum broken|future quantum problem|vulnerable to shor)\b",
            lowered,
        ):
            return "VULNERABILITY", None, None, "vulnerability"

        # 13. Report / Contradictions / Limitations / Files
        if re.search(
            r"\b(contradictions?|what couldn't you determine|what could not you determine|what can'?t you determine|what cannot you determine|what don't you know|"
            r"what do not you know|stated limitations|limitations|unknowns|report|executive summary|"
            r"how many files|files scanned|scanned files)\b",
            lowered,
        ):
            return "REPORT", None, None, "report"

        # 14. Aggregations (counts, sums, distributions, rankings)
        if re.search(r"\b(how many|count of|number of|distribution of|which language has the most|which file has the most|which algorithm appears most often)\b", lowered):
            agg = "count"
            if "distribution" in lowered:
                agg = "distribution"
            elif "most" in lowered:
                agg = "ranking"
            return "AGGREGATION", agg, None, "aggregation"

        # 14. Specific finding lookup (Entity)
        if entities or unresolved:
            return "FINDINGS_LOOKUP", None, None, "entity"

        # 14. Broad overview / Natural Language queries
        if re.search(
            r"\b(findings?|what did you find|what's going on|what have you got|show me|rundown|overview|big picture|full picture|"
            r"walk me through|what stands out|anything serious|what should i worry about|what actually matters|"
            r"what matters most|what should i care about|results?|summary)\b",
            lowered,
        ):
            return "OVERVIEW", None, None, "all"

        return "GENERAL", None, None, "all"
