#!/usr/bin/env python3
"""Validate evidence catalogs, manifests, and their cross-record bindings."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Mapping, NoReturn

import requirements as requirement_ledger

CATALOG_PATH = "conformance/evidence-catalog.toml"
LEDGER_PATH = "conformance/requirements.toml"
SCHEMA_PATH = "conformance/evidence-manifest.schema.json"
EXAMPLE_PATH = "conformance/evidence-manifest.example.json"
SCHEMA_SHA256 = "b0e137647d8ce7d999f13a1e5cae1008476d3fc850ad006d77bf6627c8540470"
TOOLCHAIN_POLICY_PATH = "conformance/toolchain-policy.toml"
TOOLCHAIN_POLICY_SHA256 = "3f125bad8eeb2ef52f3cb49d2296e9453a76b14d6d288d75b3e3fdd2fbe13095"
REGULAR_INDEX_MODE = "100644"
EXECUTABLE_INDEX_MODE = "100755"

STAGE_BINDINGS = {
    "EVID-S00-001-BASELINE": (["S00-001"], "specification-baseline"),
    "EVID-S00-002-REQUIREMENTS": (["S00-002"], "requirement-ledger"),
    "EVID-S00-003-BUILD-CONTRACT": (["S00-003"], "build-contract"),
    "EVID-S00-004-CRATE-GRAPH": (["S00-004"], "workspace-graph"),
    "EVID-S00-005-SOURCE-POLICY": (["S00-005"], "source-policy"),
    "EVID-S00-006-DEPENDENCIES": (["S00-006"], "dependency-policy"),
    "EVID-S00-007-EVIDENCE-LAYOUT": (["S00-007"], "test-evidence-layout"),
    "EVID-S00-008-TESTKIT-ISOLATION": (["S00-008"], "testkit-isolation"),
    "EVID-S00-009-CI-BASELINE": (["S00-009"], "continuous-integration"),
    "EVID-S00-010-MANIFEST-SCHEMA": (["S00-010"], "evidence-schema"),
    "EVID-S00-900-STAGE-GATE": (["S00-900"], "stage-gate"),
    "EVID-S01-001-REGISTRIES": (["S01-001"], "registry-consistency"),
    "EVID-S01-002-QUANTITIES": (["S01-002"], "bounded-quantities"),
    "EVID-S01-003-IDENTITIES": (["S01-003"], "typed-identities"),
    "EVID-S01-004-BOUNDED-VALUES": (["S01-004"], "bounded-values"),
    "EVID-S01-005-NAMES-MASKS": (["S01-005"], "canonical-names-masks"),
    "EVID-S01-006-PROTOCOL-ERRORS": (["S01-006"], "protocol-errors"),
    "EVID-S01-007-BINARY-CODEC": (["S01-007"], "canonical-binary-codec"),
    "EVID-S01-008-APPENDIX-B": (["S01-008"], "appendix-b-codecs"),
    "EVID-S01-009-TEXT-CARRIERS": (["S01-009"], "text-carriers"),
    "EVID-S01-010-PROFILE-HASHES": (["S01-010"], "source-profile-hashes"),
    "EVID-S01-011-REFERENCE-VECTORS": (["S01-011"], "reference-vectors"),
    "EVID-S01-012-TOTALITY": (["S01-012"], "totality-boundedness"),
    "EVID-S01-900-STAGE-GATE": (["S01-900"], "stage-gate"),
    "EVID-S02-001-FRAMING": (["S02-001"], "client-stream-framing"),
    "EVID-S02-002-WEBSOCKET": (["S02-002"], "websocket-semantics"),
    "EVID-S02-003-TAGS": (["S02-003"], "message-tags"),
    "EVID-S02-004-PARSER": (["S02-004"], "client-syntax-parser"),
    "EVID-S02-005-CAP": (["S02-005"], "capability-negotiation"),
    "EVID-S02-006-REGISTRATION": (["S02-006"], "registration-wire-state"),
    "EVID-S02-007-AUTH": (["S02-007"], "authentication-carriers"),
    "EVID-S02-008-RENDER": (["S02-008"], "bounded-rendering"),
    "EVID-S02-009-REPLIES": (["S02-009"], "labeled-batched-replies"),
    "EVID-S02-010-TRANSCRIPT": (["S02-010"], "client-transcripts"),
    "EVID-S02-011-FUZZ": (["S02-011"], "client-wire-fuzzing"),
    "EVID-S02-900-STAGE-GATE": (["S02-900"], "stage-gate"),
    "EVID-S03-001-IDENTITIES": (["S03-001"], "domain-identity-lifecycle"),
    "EVID-S03-002-CHANNELS": (["S03-002"], "channel-state-model"),
    "EVID-S03-003-PROJECTIONS": (["S03-003"], "privacy-projections"),
    "EVID-S03-004-COMMANDS": (["S03-004"], "canonical-domain-commands"),
    "EVID-S03-005-AUTHORIZATION": (["S03-005"], "authorization-rate-policy"),
    "EVID-S03-006-DELIVERY-PLANS": (["S03-006"], "channel-direct-message-plans"),
    "EVID-S03-007-MODERATION": (["S03-007"], "moderation-safety-plans"),
    "EVID-S03-008-HISTORY-E2EE": (["S03-008"], "history-e2ee-policy"),
    "EVID-S03-009-MUTATION-PLANS": (["S03-009"], "pure-mutation-plans"),
    "EVID-S03-010-EXPLICIT-INPUTS": (["S03-010"], "explicit-time-entropy-inputs"),
    "EVID-S03-011-REFERENCE-MODEL": (["S03-011"], "independent-reference-model"),
    "EVID-S03-012-SEQUENCES": (["S03-012"], "generated-domain-sequences"),
    "EVID-S03-900-STAGE-GATE": (["S03-900"], "stage-gate"),
    "EVID-S04-001-SECRETS": (["S04-001"], "secret-bearing-wrappers"),
    "EVID-S04-002-ENTROPY": (["S04-002"], "operating-system-entropy"),
    "EVID-S04-003-DOMAIN-KDFS": (["S04-003"], "domain-hash-mac-kdf"),
    "EVID-S04-004-STORAGE-AEAD": (["S04-004"], "storage-aead-adapter"),
    "EVID-S04-005-SIGNATURES": (["S04-005"], "strict-signature-adapter"),
    "EVID-S04-006-HPKE": (["S04-006"], "account-service-hpke"),
    "EVID-S04-007-OPAQUE": (["S04-007"], "opaque-profile"),
    "EVID-S04-008-CREATION": (["S04-008"], "account-creation-state"),
    "EVID-S04-009-AUTHENTICATION": (["S04-009"], "account-authentication-state"),
    "EVID-S04-010-COMPLETIONS": (["S04-010"], "authenticated-completion-receipts"),
    "EVID-S04-011-DESTRUCTIVE-AUTH": (["S04-011"], "credential-deletion-authorization"),
    "EVID-S04-012-WORKERS": (["S04-012"], "bounded-crypto-workers"),
    "EVID-S04-013-DEPENDENCIES": (["S04-013"], "cryptographic-dependency-profile"),
    "EVID-S04-014-VERIFICATION": (["S04-014"], "crypto-auth-verification"),
    "EVID-S04-900-STAGE-GATE": (["S04-900"], "stage-gate"),
    "EVID-S05-001-SCHEMA": (["S05-001"], "storage-schema-codecs"),
    "EVID-S05-002-SEALED-RECORDS": (["S05-002"], "sealed-storage-records"),
    "EVID-S05-003-ACCOUNTING": (["S05-003"], "storage-accounting"),
    "EVID-S05-004-MUTATIONS": (["S05-004"], "storage-mutation-batches"),
    "EVID-S05-005-OWNER": (["S05-005"], "single-storage-owner"),
    "EVID-S05-006-COMMIT": (["S05-006"], "storage-two-phase-commit"),
    "EVID-S05-007-NONCES": (["S05-007"], "storage-nonce-reservations"),
    "EVID-S05-008-INTEGRITY": (["S05-008"], "storage-integrity-ledger"),
    "EVID-S05-009-GUARD": (["S05-009"], "external-rollback-guard"),
    "EVID-S05-010-RECOVERY": (["S05-010"], "storage-startup-recovery"),
    "EVID-S05-011-MIGRATIONS": (["S05-011"], "storage-migration-construction"),
    "EVID-S05-012-BACKUP": (["S05-012"], "storage-backup-restore"),
    "EVID-S05-013-REKEY": (["S05-013"], "storage-deletion-rekey"),
    "EVID-S05-014-LOGIN-INDEX": (["S05-014"], "login-index-transition"),
    "EVID-S05-015-QUALIFICATION": (["S05-015"], "storage-fault-qualification"),
    "EVID-S05-900-STAGE-GATE": (["S05-900"], "stage-gate"),
    "EVID-S06-001-CONFIGURATION": (["S06-001"], "strict-configuration"),
    "EVID-S06-002-INITIALIZATION": (["S06-002"], "node-initialization"),
    "EVID-S06-003-TLS": (["S06-003"], "tls-endpoints"),
    "EVID-S06-004-TRANSPORTS": (["S06-004"], "transport-profile-isolation"),
    "EVID-S06-005-TASK-TREE": (["S06-005"], "runtime-task-tree"),
    "EVID-S06-006-MEMORY": (["S06-006"], "memory-admission"),
    "EVID-S06-007-CONNECTIONS": (["S06-007"], "connection-output-owners"),
    "EVID-S06-008-STATE-CORE": (["S06-008"], "state-core-durability"),
    "EVID-S06-009-SESSIONS": (["S06-009"], "registration-session-routing"),
    "EVID-S06-010-MESSAGING": (["S06-010"], "single-node-messaging"),
    "EVID-S06-011-ADMISSION": (["S06-011"], "timers-admission-overload"),
    "EVID-S06-012-ADMIN": (["S06-012"], "isolated-administration"),
    "EVID-S06-013-RELOAD": (["S06-013"], "atomic-live-reload"),
    "EVID-S06-014-OBSERVABILITY": (["S06-014"], "privacy-observability"),
    "EVID-S06-015-HARDENING": (["S06-015"], "service-hardening"),
    "EVID-S06-900-STAGE-GATE": (["S06-900"], "stage-gate"),
    "EVID-S07-001-TRANSPORT": (["S07-001"], "federation-transport"),
    "EVID-S07-002-HELLO": (["S07-002"], "federation-hello"),
    "EVID-S07-003-AUTHORITY": (["S07-003"], "coordinator-authority"),
    "EVID-S07-004-ORIGINS": (["S07-004"], "origin-lifecycle"),
    "EVID-S07-005-REQUESTS": (["S07-005"], "idempotent-requests"),
    "EVID-S07-006-PROJECTIONS": (["S07-006"], "least-information-projections"),
    "EVID-S07-007-ACKS": (["S07-007"], "durable-event-acknowledgement"),
    "EVID-S07-008-OBJECTS": (["S07-008"], "bounded-object-transport"),
    "EVID-S07-009-SNAPSHOTS": (["S07-009"], "snapshot-resume"),
    "EVID-S07-010-PARTITIONS": (["S07-010"], "partition-keepalive-recovery"),
    "EVID-S07-011-QUERIES": (["S07-011"], "paged-directory-queries"),
    "EVID-S07-012-MODEL": (["S07-012"], "bounded-federation-model"),
    "EVID-S07-013-INTEROP": (["S07-013"], "multi-process-federation"),
    "EVID-S07-900-STAGE-GATE": (["S07-900"], "stage-gate"),
    "EVID-S08-001-PROFILE": (["S08-001"], "exact-profile-negotiation"),
    "EVID-S08-002-SEPARATION": (["S08-002"], "daemon-client-separation"),
    "EVID-S08-003-IDENTITY": (["S08-003"], "public-identity-validation"),
    "EVID-S08-004-ROUTES": (["S08-004"], "route-identity-binding-locks"),
    "EVID-S08-005-AUTHORITY": (["S08-005"], "sequencer-policy-finality-authority"),
    "EVID-S08-006-CONTEXT": (["S08-006"], "mls-context-envelopes"),
    "EVID-S08-007-CARRIERS": (["S08-007"], "client-carriers-reassembly"),
    "EVID-S08-008-SEQUENCING": (["S08-008"], "candidate-receipt-finality"),
    "EVID-S08-009-FEDERATION": (["S08-009"], "companion-federation-exchange"),
    "EVID-S08-010-LIFECYCLE": (["S08-010"], "server-visible-group-lifecycle"),
    "EVID-S08-011-REMOVAL": (["S08-011"], "removal-revocation-recovery-gates"),
    "EVID-S08-012-REINIT": (["S08-012"], "reinit-route-migration"),
    "EVID-S08-013-PERSISTENCE": (["S08-013"], "replay-mailbox-persistence"),
    "EVID-S08-014-LIMITS": (["S08-014"], "resource-timing-limits"),
    "EVID-S08-015-DOWNGRADE": (["S08-015"], "downgrade-reset-failure"),
    "EVID-S08-016-BARRIER": (["S08-016"], "cross-profile-durable-barrier"),
    "EVID-S08-017-INTEGRATION": (["S08-017"], "encrypted-node-integration"),
    "EVID-S08-018-CORPUS": (["S08-018"], "mls-corpus-pin"),
    "EVID-S08-019-VECTORS": (["S08-019"], "independent-object-vectors"),
    "EVID-S08-020-INTEROP": (["S08-020"], "cross-implementation-mls"),
    "EVID-S08-021-PLAINTEXT": (["S08-021"], "plaintext-rejection-matrix"),
    "EVID-S08-022-BOUNDARIES": (["S08-022"], "limit-padding-boundaries"),
    "EVID-S08-023-FUZZ": (["S08-023"], "parser-fuzzing"),
    "EVID-S08-024-ADVERSARIAL": (["S08-024"], "stateful-adversarial-properties"),
    "EVID-S08-025-CRASH": (["S08-025"], "durable-boundary-crash-tests"),
    "EVID-S08-026-QUORUM": (["S08-026"], "finality-quorum-exhaustion"),
    "EVID-S08-027-TRANSITIONS": (["S08-027"], "identity-roster-transitions"),
    "EVID-S08-028-LOAD": (["S08-028"], "maximum-shape-load"),
    "EVID-S08-029-CANARIES": (["S08-029"], "log-telemetry-canaries"),
    "EVID-S08-030-REINIT-RACES": (["S08-030"], "reinit-race-matrix"),
    "EVID-S08-031-ECAP": (["S08-031"], "ecap-federation-transitions"),
    "EVID-S08-032-WIRE-BUDGET": (["S08-032"], "mechanical-wire-budget"),
    "EVID-S08-033-SEMANTIC-IDS": (["S08-033"], "semantic-id-malleability"),
    "EVID-S08-034-COUNCIL": (["S08-034"], "finality-council-transitions"),
    "EVID-S08-035-OPERATIONS": (["S08-035"], "federation-operation-semantics"),
    "EVID-S08-036-IDEMPOTENCY": (["S08-036"], "idempotency-crash-tests"),
    "EVID-S08-037-CHAINS": (["S08-037"], "root-binding-chains"),
    "EVID-S08-038-SCHEDULES": (["S08-038"], "barrier-schedules"),
    "EVID-S08-039-REVIEW": (["S08-039"], "external-review"),
    "EVID-S08-040-POLICY-PUBLICATION": (["S08-040"], "policy-publication"),
    "EVID-S08-041-QUORUM-GUARD": (["S08-041"], "sequencer-quorum-guard"),
    "EVID-S08-042-CHAIN-WITNESS": (["S08-042"], "edge-chain-witness"),
    "EVID-S08-043-CONTENT-PADDING": (["S08-043"], "application-content-padding"),
    "EVID-S08-044-REAL-CLIENTS": (["S08-044"], "real-client-lifecycle"),
    "EVID-S08-900-STAGE-GATE": (["S08-900"], "stage-gate"),
    "EVID-S09-001-WSS": (["S09-001"], "wss-profile"),
    "EVID-S09-002-EQUIVALENCE": (["S09-002"], "transport-equivalence"),
    "EVID-S09-003-HISTORY": (["S09-003"], "plaintext-history"),
    "EVID-S09-004-ENCRYPTED-EXCLUSION": (["S09-004"], "encrypted-history-exclusion"),
    "EVID-S09-005-PROFILE-MATRIX": (["S09-005"], "optional-profile-matrix"),
    "EVID-S09-900-STAGE-GATE": (["S09-900"], "stage-gate"),
}

NORMATIVE_BINDINGS = {
    "EVID-ARCH-AUTH-03": (["ARCH-AUTH-03"], "normative-requirement"),
    "EVID-ARCH-AUTH-06": (["ARCH-AUTH-06"], "normative-requirement"),
    "EVID-ARCH-FED-01": (["ARCH-FED-01"], "normative-requirement"),
    "EVID-ARCH-FED-04": (["ARCH-FED-04"], "normative-requirement"),
    "EVID-ARCH-FED-05": (["ARCH-FED-05"], "normative-requirement"),
    "EVID-ARCH-FED-06": (["ARCH-FED-06"], "normative-requirement"),
    "EVID-ARCH-FED-07": (["ARCH-FED-07"], "normative-requirement"),
    "EVID-ARCH-FED-08": (["ARCH-FED-08"], "normative-requirement"),
    "EVID-ARCH-FED-09": (["ARCH-FED-09"], "normative-requirement"),
    "EVID-ARCH-FED-13": (["ARCH-FED-13"], "normative-requirement"),
    "EVID-ARCH-ID-05": (["ARCH-ID-05"], "normative-requirement"),
    "EVID-ARCH-REQ-0B5E5D62113344CD5B9E": (["ARCH-REQ-0B5E5D62113344CD5B9E"], "normative-requirement"),
    "EVID-ARCH-REQ-17B30148DD5160683953": (["ARCH-REQ-17B30148DD5160683953"], "normative-requirement"),
    "EVID-ARCH-REQ-32BBA90BC88CB72E6AD1": (["ARCH-REQ-32BBA90BC88CB72E6AD1"], "normative-requirement"),
    "EVID-ARCH-REQ-415192C9AE3C7492C527": (["ARCH-REQ-415192C9AE3C7492C527"], "normative-requirement"),
    "EVID-ARCH-REQ-A028640A3B71B72E5F38": (["ARCH-REQ-A028640A3B71B72E5F38"], "normative-requirement"),
    "EVID-ARCH-REQ-A1C186F162F73F71282D": (["ARCH-REQ-A1C186F162F73F71282D"], "normative-requirement"),
    "EVID-ARCH-STA-01": (["ARCH-STA-01"], "normative-requirement"),
    "EVID-ARCH-STA-03": (["ARCH-STA-03"], "normative-requirement"),
    "EVID-ARCH-STA-06": (["ARCH-STA-06"], "normative-requirement"),
    "EVID-ARCH-STA-07": (["ARCH-STA-07"], "normative-requirement"),
    "EVID-ARCH-STA-10": (["ARCH-STA-10"], "normative-requirement"),
    "EVID-ARCH-TRN-01": (["ARCH-TRN-01"], "normative-requirement"),
    "EVID-ARCH-TRN-03": (["ARCH-TRN-03"], "normative-requirement"),
    "EVID-ARCH-AUTH-01": (["ARCH-AUTH-01"], "normative-requirement"),
    "EVID-ARCH-AUTH-04": (["ARCH-AUTH-04"], "normative-requirement"),
    "EVID-ARCH-AUTH-09": (["ARCH-AUTH-09"], "normative-requirement"),
    "EVID-ARCH-AUTH-10": (["ARCH-AUTH-10"], "normative-requirement"),
    "EVID-ARCH-REQ-3BFE92E0E09C7C1C45E5": (
        ["ARCH-REQ-3BFE92E0E09C7C1C45E5"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-48ECE41B610BE7FF1950": (
        ["ARCH-REQ-48ECE41B610BE7FF1950"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-49AAC75AD4C65F0466B2": (
        ["ARCH-REQ-49AAC75AD4C65F0466B2"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-78FAB57061FA01E1805E": (
        ["ARCH-REQ-78FAB57061FA01E1805E"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-B45135D9F5992114B394": (
        ["ARCH-REQ-B45135D9F5992114B394"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-F3D92EF9C888E0675CB4": (
        ["ARCH-REQ-F3D92EF9C888E0675CB4"],
        "normative-requirement",
    ),
    "EVID-E2EE-REQ-1CF30FAFE8FA36F5CF2E": (
        ["E2EE-REQ-1CF30FAFE8FA36F5CF2E"],
        "normative-requirement",
    ),
    "EVID-E2EE-REQ-A0EFEAB7474EA0A450F5": (
        ["E2EE-REQ-A0EFEAB7474EA0A450F5"],
        "normative-requirement",
    ),
    "EVID-ARCH-REQ-CAFA64060EE32DC7419D": (
        ["ARCH-REQ-CAFA64060EE32DC7419D"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-D621F68B6C389E5B7660": (
        ["ARCH-REQ-D621F68B6C389E5B7660"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-30183AFAFED8128B6541": (
        ["ARCH-REQ-30183AFAFED8128B6541"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-497991387ADD6957DDBE": (
        ["ARCH-REQ-497991387ADD6957DDBE"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-61DDBED6FB176354A9BF": (
        ["ARCH-REQ-61DDBED6FB176354A9BF"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-61C6AFF8B1137410D0FD": (
        ["ARCH-REQ-61C6AFF8B1137410D0FD"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-EE3343E6DDAA279E4E23": (
        ["ARCH-REQ-EE3343E6DDAA279E4E23"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-29DE85F5026ADD8EF114": (
        ["ARCH-REQ-29DE85F5026ADD8EF114"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-F235013D840DBE992D6C": (
        ["ARCH-REQ-F235013D840DBE992D6C"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-C70A2FA24AD661DB7BC3": (
        ["ARCH-REQ-C70A2FA24AD661DB7BC3"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-2DAB3DDD73C2AE873977": (
        ["ARCH-REQ-2DAB3DDD73C2AE873977"], "normative-requirement",
    ),
    "EVID-ARCH-REQ-351F91DD2F9F7B09DD4C": (
        ["ARCH-REQ-351F91DD2F9F7B09DD4C"], "normative-requirement",
    ),
    "EVID-ARCH-ID-07": (["ARCH-ID-07"], "normative-requirement"),
    "EVID-ARCH-DUR-03": (["ARCH-DUR-03"], "normative-requirement"),
    "EVID-ARCH-DUR-04": (["ARCH-DUR-04"], "normative-requirement"),
    "EVID-ARCH-DUR-05": (["ARCH-DUR-05"], "normative-requirement"),
    "EVID-ARCH-DUR-06": (["ARCH-DUR-06"], "normative-requirement"),
    "EVID-ARCH-DUR-07": (["ARCH-DUR-07"], "normative-requirement"),
    "EVID-ARCH-DUR-08": (["ARCH-DUR-08"], "normative-requirement"),
    "EVID-ARCH-DUR-09": (["ARCH-DUR-09"], "normative-requirement"),
    "EVID-ARCH-DUR-10": (["ARCH-DUR-10"], "normative-requirement"),
    "EVID-ARCH-DUR-11": (["ARCH-DUR-11"], "normative-requirement"),
    "EVID-ARCH-DUR-12": (["ARCH-DUR-12"], "normative-requirement"),
    "EVID-ARCH-AUTH-02": (["ARCH-AUTH-02"], "normative-requirement"),
    "EVID-ARCH-AUTH-05": (["ARCH-AUTH-05"], "normative-requirement"),
    "EVID-ARCH-AUTH-07": (["ARCH-AUTH-07"], "normative-requirement"),
    "EVID-ARCH-AUTH-08": (["ARCH-AUTH-08"], "normative-requirement"),
    "EVID-ARCH-AUTH-11": (["ARCH-AUTH-11"], "normative-requirement"),
    "EVID-ARCH-ID-03": (["ARCH-ID-03"], "normative-requirement"),
    "EVID-ARCH-ID-04": (["ARCH-ID-04"], "normative-requirement"),
    "EVID-ARCH-OPS-02": (["ARCH-OPS-02"], "normative-requirement"),
    "EVID-ARCH-OPS-03": (["ARCH-OPS-03"], "normative-requirement"),
    "EVID-ARCH-OPS-05": (["ARCH-OPS-05"], "normative-requirement"),
    "EVID-ARCH-REQ-081595C2CCFFAF608E38": (["ARCH-REQ-081595C2CCFFAF608E38"], "normative-requirement"),
    "EVID-ARCH-REQ-0A2DFA591F93494434CA": (["ARCH-REQ-0A2DFA591F93494434CA"], "normative-requirement"),
    "EVID-ARCH-REQ-0EC008E51ACF33B486A7": (["ARCH-REQ-0EC008E51ACF33B486A7"], "normative-requirement"),
    "EVID-ARCH-REQ-0ED2BB6143B32AC67530": (["ARCH-REQ-0ED2BB6143B32AC67530"], "normative-requirement"),
    "EVID-ARCH-REQ-1077079A5B8E236B2E7E": (["ARCH-REQ-1077079A5B8E236B2E7E"], "normative-requirement"),
    "EVID-ARCH-REQ-1BC68D62C88F9901863C": (["ARCH-REQ-1BC68D62C88F9901863C"], "normative-requirement"),
    "EVID-ARCH-REQ-1F847B93E38E57D5492E": (["ARCH-REQ-1F847B93E38E57D5492E"], "normative-requirement"),
    "EVID-ARCH-REQ-239F20852008EFEBC14C": (["ARCH-REQ-239F20852008EFEBC14C"], "normative-requirement"),
    "EVID-ARCH-REQ-2DE781FEE0904A7D417F": (["ARCH-REQ-2DE781FEE0904A7D417F"], "normative-requirement"),
    "EVID-ARCH-REQ-3EDADEB5374091A7FCD9": (["ARCH-REQ-3EDADEB5374091A7FCD9"], "normative-requirement"),
    "EVID-ARCH-REQ-437D151873A9CD5C587B": (["ARCH-REQ-437D151873A9CD5C587B"], "normative-requirement"),
    "EVID-ARCH-REQ-533C4FC96F4E21250FF2": (["ARCH-REQ-533C4FC96F4E21250FF2"], "normative-requirement"),
    "EVID-ARCH-REQ-6ED8CC0935B62D48C171": (["ARCH-REQ-6ED8CC0935B62D48C171"], "normative-requirement"),
    "EVID-ARCH-REQ-76933F949C4BA311D15E": (["ARCH-REQ-76933F949C4BA311D15E"], "normative-requirement"),
    "EVID-ARCH-REQ-89A52EAEFEB27B78EA3F": (["ARCH-REQ-89A52EAEFEB27B78EA3F"], "normative-requirement"),
    "EVID-ARCH-REQ-8E6BD0E1ADFA47B0488A": (["ARCH-REQ-8E6BD0E1ADFA47B0488A"], "normative-requirement"),
    "EVID-ARCH-REQ-91A4F778BFA1744C7579": (["ARCH-REQ-91A4F778BFA1744C7579"], "normative-requirement"),
    "EVID-ARCH-REQ-951E6893F2B754847C8E": (["ARCH-REQ-951E6893F2B754847C8E"], "normative-requirement"),
    "EVID-ARCH-REQ-97C72A89521508665EA0": (["ARCH-REQ-97C72A89521508665EA0"], "normative-requirement"),
    "EVID-ARCH-REQ-A8B38178C6FCDD5EB7ED": (["ARCH-REQ-A8B38178C6FCDD5EB7ED"], "normative-requirement"),
    "EVID-ARCH-REQ-AC500B2D79C7A16B554A": (["ARCH-REQ-AC500B2D79C7A16B554A"], "normative-requirement"),
    "EVID-ARCH-REQ-AF83DC2BF6651C1ADCAB": (["ARCH-REQ-AF83DC2BF6651C1ADCAB"], "normative-requirement"),
    "EVID-ARCH-REQ-B640E662E68B7720C8CE": (["ARCH-REQ-B640E662E68B7720C8CE"], "normative-requirement"),
    "EVID-ARCH-REQ-C33F2C188FAB745A4008": (["ARCH-REQ-C33F2C188FAB745A4008"], "normative-requirement"),
    "EVID-ARCH-REQ-D8752DA6EC2A4D543D27": (["ARCH-REQ-D8752DA6EC2A4D543D27"], "normative-requirement"),
    "EVID-ARCH-REQ-D9709F92FF869A201DA0": (["ARCH-REQ-D9709F92FF869A201DA0"], "normative-requirement"),
    "EVID-ARCH-REQ-DE27E4D7727B11384C1F": (["ARCH-REQ-DE27E4D7727B11384C1F"], "normative-requirement"),
    "EVID-ARCH-STA-04": (["ARCH-STA-04"], "normative-requirement"),
    "EVID-ARCH-TRN-02": (["ARCH-TRN-02"], "normative-requirement"),
    "EVID-ARCH-CON-01": (["ARCH-CON-01"], "normative-requirement"),
    "EVID-ARCH-CON-02": (["ARCH-CON-02"], "normative-requirement"),
    "EVID-ARCH-CON-03": (["ARCH-CON-03"], "normative-requirement"),
    "EVID-ARCH-CON-04": (["ARCH-CON-04"], "normative-requirement"),
    "EVID-ARCH-CON-05": (["ARCH-CON-05"], "normative-requirement"),
    "EVID-ARCH-DUR-01": (["ARCH-DUR-01"], "normative-requirement"),
    "EVID-ARCH-DUR-02": (["ARCH-DUR-02"], "normative-requirement"),
    "EVID-ARCH-E2E-01": (["ARCH-E2E-01"], "normative-requirement"),
    "EVID-ARCH-E2E-02": (["ARCH-E2E-02"], "normative-requirement"),
    "EVID-ARCH-E2E-03": (["ARCH-E2E-03"], "normative-requirement"),
    "EVID-ARCH-E2E-04": (["ARCH-E2E-04"], "normative-requirement"),
    "EVID-ARCH-E2E-05": (["ARCH-E2E-05"], "normative-requirement"),
    "EVID-ARCH-E2E-06": (["ARCH-E2E-06"], "normative-requirement"),
    "EVID-ARCH-E2E-07": (["ARCH-E2E-07"], "normative-requirement"),
    "EVID-ARCH-FED-02": (["ARCH-FED-02"], "normative-requirement"),
    "EVID-ARCH-FED-03": (["ARCH-FED-03"], "normative-requirement"),
    "EVID-ARCH-FED-10": (["ARCH-FED-10"], "normative-requirement"),
    "EVID-ARCH-FED-11": (["ARCH-FED-11"], "normative-requirement"),
    "EVID-ARCH-FED-12": (["ARCH-FED-12"], "normative-requirement"),
    "EVID-ARCH-ID-01": (["ARCH-ID-01"], "normative-requirement"),
    "EVID-ARCH-ID-02": (["ARCH-ID-02"], "normative-requirement"),
    "EVID-ARCH-ID-06": (["ARCH-ID-06"], "normative-requirement"),
    "EVID-ARCH-REQ-00FBB19D3A47F35629EA": (["ARCH-REQ-00FBB19D3A47F35629EA"], "normative-requirement"),
    "EVID-ARCH-REQ-630535C69EC8B9414843": (["ARCH-REQ-630535C69EC8B9414843"], "normative-requirement"),
    "EVID-ARCH-REQ-705219A4555AC2842B77": (["ARCH-REQ-705219A4555AC2842B77"], "normative-requirement"),
    "EVID-ARCH-REQ-D74CDEA02D46EEA2E9AD": (["ARCH-REQ-D74CDEA02D46EEA2E9AD"], "normative-requirement"),
    "EVID-ARCH-REQ-D8DDA49F3C32422D93B3": (["ARCH-REQ-D8DDA49F3C32422D93B3"], "normative-requirement"),
    "EVID-ARCH-REQ-E592762A378E0D95835A": (["ARCH-REQ-E592762A378E0D95835A"], "normative-requirement"),
    "EVID-ARCH-REQ-F236FC1F5FD8129AB518": (["ARCH-REQ-F236FC1F5FD8129AB518"], "normative-requirement"),
    "EVID-ARCH-STA-02": (["ARCH-STA-02"], "normative-requirement"),
    "EVID-ARCH-STA-08": (["ARCH-STA-08"], "normative-requirement"),
    "EVID-ARCH-TRN-04": (["ARCH-TRN-04"], "normative-requirement"),
    "EVID-ARCH-TRN-05": (["ARCH-TRN-05"], "normative-requirement"),
    "EVID-ARCH-TRN-06": (["ARCH-TRN-06"], "normative-requirement"),
    "EVID-E2EE-REQ-03E795692C36DFAE083B": (["E2EE-REQ-03E795692C36DFAE083B"], "normative-requirement"),
    "EVID-E2EE-REQ-04B0129952BBBB1F3D22": (["E2EE-REQ-04B0129952BBBB1F3D22"], "normative-requirement"),
    "EVID-E2EE-REQ-0950B248DBB87C569FE7": (["E2EE-REQ-0950B248DBB87C569FE7"], "normative-requirement"),
    "EVID-E2EE-REQ-0DAEDE4522366E3A68A9": (["E2EE-REQ-0DAEDE4522366E3A68A9"], "normative-requirement"),
    "EVID-E2EE-REQ-0EE614CD32C84FA9F408": (["E2EE-REQ-0EE614CD32C84FA9F408"], "normative-requirement"),
    "EVID-E2EE-REQ-1AB78DA63741FF0B38CF": (["E2EE-REQ-1AB78DA63741FF0B38CF"], "normative-requirement"),
    "EVID-E2EE-REQ-1BFDC5AC26176497302E": (["E2EE-REQ-1BFDC5AC26176497302E"], "normative-requirement"),
    "EVID-E2EE-REQ-208C5CAB7399B4AC15B8": (["E2EE-REQ-208C5CAB7399B4AC15B8"], "normative-requirement"),
    "EVID-E2EE-REQ-21F466D08365E6787EFF": (["E2EE-REQ-21F466D08365E6787EFF"], "normative-requirement"),
    "EVID-E2EE-REQ-28CC5A2874FBFEDC8694": (["E2EE-REQ-28CC5A2874FBFEDC8694"], "normative-requirement"),
    "EVID-E2EE-REQ-2F0777EEA2E2B0559F6D": (["E2EE-REQ-2F0777EEA2E2B0559F6D"], "normative-requirement"),
    "EVID-E2EE-REQ-37736EFE55D201CBE671": (["E2EE-REQ-37736EFE55D201CBE671"], "normative-requirement"),
    "EVID-E2EE-REQ-37CAE24A086303163D86": (["E2EE-REQ-37CAE24A086303163D86"], "normative-requirement"),
    "EVID-E2EE-REQ-3AE1FE848688A346F9F1": (["E2EE-REQ-3AE1FE848688A346F9F1"], "normative-requirement"),
    "EVID-E2EE-REQ-3DDAFB884DFFB22C1F74": (["E2EE-REQ-3DDAFB884DFFB22C1F74"], "normative-requirement"),
    "EVID-E2EE-REQ-3DFFF778DA62F4CEEF8F": (["E2EE-REQ-3DFFF778DA62F4CEEF8F"], "normative-requirement"),
    "EVID-E2EE-REQ-3F31F96A8E03DA4C101C": (["E2EE-REQ-3F31F96A8E03DA4C101C"], "normative-requirement"),
    "EVID-E2EE-REQ-3F6EB7E7803E9A17D029": (["E2EE-REQ-3F6EB7E7803E9A17D029"], "normative-requirement"),
    "EVID-E2EE-REQ-47F62E0752E7757399CD": (["E2EE-REQ-47F62E0752E7757399CD"], "normative-requirement"),
    "EVID-E2EE-REQ-48C5B151716A5DA59976": (["E2EE-REQ-48C5B151716A5DA59976"], "normative-requirement"),
    "EVID-E2EE-REQ-4A2736C8DC8339780AA6": (["E2EE-REQ-4A2736C8DC8339780AA6"], "normative-requirement"),
    "EVID-E2EE-REQ-4A2B327FEB0ED0D66724": (["E2EE-REQ-4A2B327FEB0ED0D66724"], "normative-requirement"),
    "EVID-E2EE-REQ-4B9FA0731463AF395EEF": (["E2EE-REQ-4B9FA0731463AF395EEF"], "normative-requirement"),
    "EVID-E2EE-REQ-4E4E130CEAB680D99587": (["E2EE-REQ-4E4E130CEAB680D99587"], "normative-requirement"),
    "EVID-E2EE-REQ-4ECEEB84B918BCA2DBE3": (["E2EE-REQ-4ECEEB84B918BCA2DBE3"], "normative-requirement"),
    "EVID-E2EE-REQ-4EFBE464A39690115414": (["E2EE-REQ-4EFBE464A39690115414"], "normative-requirement"),
    "EVID-E2EE-REQ-532CF56360A03DCF3C39": (["E2EE-REQ-532CF56360A03DCF3C39"], "normative-requirement"),
    "EVID-E2EE-REQ-54D3BF177A5D79854AEC": (["E2EE-REQ-54D3BF177A5D79854AEC"], "normative-requirement"),
    "EVID-E2EE-REQ-5B3475BE0506C311BEF2": (["E2EE-REQ-5B3475BE0506C311BEF2"], "normative-requirement"),
    "EVID-E2EE-REQ-5B7791BEAEA4EF6B0D60": (["E2EE-REQ-5B7791BEAEA4EF6B0D60"], "normative-requirement"),
    "EVID-E2EE-REQ-67059195AB3AA10AAD9B": (["E2EE-REQ-67059195AB3AA10AAD9B"], "normative-requirement"),
    "EVID-E2EE-REQ-6A1A40DF827404DFC2E0": (["E2EE-REQ-6A1A40DF827404DFC2E0"], "normative-requirement"),
    "EVID-E2EE-REQ-72ECA857E694D0439A70": (["E2EE-REQ-72ECA857E694D0439A70"], "normative-requirement"),
    "EVID-E2EE-REQ-73270B473C2AB773AF11": (["E2EE-REQ-73270B473C2AB773AF11"], "normative-requirement"),
    "EVID-E2EE-REQ-74E9B5BFDE9BE0345707": (["E2EE-REQ-74E9B5BFDE9BE0345707"], "normative-requirement"),
    "EVID-E2EE-REQ-75819BD50FB3E71F2B91": (["E2EE-REQ-75819BD50FB3E71F2B91"], "normative-requirement"),
    "EVID-E2EE-REQ-7FE02BCBD9EEB3934B70": (["E2EE-REQ-7FE02BCBD9EEB3934B70"], "normative-requirement"),
    "EVID-E2EE-REQ-845B04F1228AFD8867F1": (["E2EE-REQ-845B04F1228AFD8867F1"], "normative-requirement"),
    "EVID-E2EE-REQ-865E52D8D04B59FEEFBE": (["E2EE-REQ-865E52D8D04B59FEEFBE"], "normative-requirement"),
    "EVID-E2EE-REQ-87B4B4DBBAD9DB97F76A": (["E2EE-REQ-87B4B4DBBAD9DB97F76A"], "normative-requirement"),
    "EVID-E2EE-REQ-8AB2B222BF622D4C4BDF": (["E2EE-REQ-8AB2B222BF622D4C4BDF"], "normative-requirement"),
    "EVID-E2EE-REQ-8B777BE6D9A7ED988687": (["E2EE-REQ-8B777BE6D9A7ED988687"], "normative-requirement"),
    "EVID-E2EE-REQ-8C607B4410F376797BD2": (["E2EE-REQ-8C607B4410F376797BD2"], "normative-requirement"),
    "EVID-E2EE-REQ-9641FAA02EEEC75A2E7D": (["E2EE-REQ-9641FAA02EEEC75A2E7D"], "normative-requirement"),
    "EVID-E2EE-REQ-98421AA3C0425E259F8F": (["E2EE-REQ-98421AA3C0425E259F8F"], "normative-requirement"),
    "EVID-E2EE-REQ-986A7772723E16360520": (["E2EE-REQ-986A7772723E16360520"], "normative-requirement"),
    "EVID-E2EE-REQ-98C7F0834891533DE1BC": (["E2EE-REQ-98C7F0834891533DE1BC"], "normative-requirement"),
    "EVID-E2EE-REQ-9A4E05845BDB4B1C7D30": (["E2EE-REQ-9A4E05845BDB4B1C7D30"], "normative-requirement"),
    "EVID-E2EE-REQ-9EA1028E2CE3115F5EEB": (["E2EE-REQ-9EA1028E2CE3115F5EEB"], "normative-requirement"),
    "EVID-E2EE-REQ-A141AC00A13A398685DC": (["E2EE-REQ-A141AC00A13A398685DC"], "normative-requirement"),
    "EVID-E2EE-REQ-A5E4E2058896C2016403": (["E2EE-REQ-A5E4E2058896C2016403"], "normative-requirement"),
    "EVID-E2EE-REQ-A7C32D4A15F7F0AF4F82": (["E2EE-REQ-A7C32D4A15F7F0AF4F82"], "normative-requirement"),
    "EVID-E2EE-REQ-AC36B134578CBDB4F7A2": (["E2EE-REQ-AC36B134578CBDB4F7A2"], "normative-requirement"),
    "EVID-E2EE-REQ-B1A07872530E53E1C5E0": (["E2EE-REQ-B1A07872530E53E1C5E0"], "normative-requirement"),
    "EVID-E2EE-REQ-B341221DC3B1063B9F41": (["E2EE-REQ-B341221DC3B1063B9F41"], "normative-requirement"),
    "EVID-E2EE-REQ-B73C16A97C1278CDDE0B": (["E2EE-REQ-B73C16A97C1278CDDE0B"], "normative-requirement"),
    "EVID-E2EE-REQ-B8F44A765000AE5B6944": (["E2EE-REQ-B8F44A765000AE5B6944"], "normative-requirement"),
    "EVID-E2EE-REQ-B93A7B094027B1B00105": (["E2EE-REQ-B93A7B094027B1B00105"], "normative-requirement"),
    "EVID-E2EE-REQ-B99A6DD4949FED0CE02A": (["E2EE-REQ-B99A6DD4949FED0CE02A"], "normative-requirement"),
    "EVID-E2EE-REQ-BFA20A50D15399A2F088": (["E2EE-REQ-BFA20A50D15399A2F088"], "normative-requirement"),
    "EVID-E2EE-REQ-C345CFA457EB0B500D2A": (["E2EE-REQ-C345CFA457EB0B500D2A"], "normative-requirement"),
    "EVID-E2EE-REQ-C8997B4345158FD54D44": (["E2EE-REQ-C8997B4345158FD54D44"], "normative-requirement"),
    "EVID-E2EE-REQ-CA268835A931F5051D79": (["E2EE-REQ-CA268835A931F5051D79"], "normative-requirement"),
    "EVID-E2EE-REQ-CED437B1C62CF9CD0A79": (["E2EE-REQ-CED437B1C62CF9CD0A79"], "normative-requirement"),
    "EVID-E2EE-REQ-D07C2C1AA58D16CA582D": (["E2EE-REQ-D07C2C1AA58D16CA582D"], "normative-requirement"),
    "EVID-E2EE-REQ-D150C4C93D931F51EE12": (["E2EE-REQ-D150C4C93D931F51EE12"], "normative-requirement"),
    "EVID-E2EE-REQ-D2C711B6BB260BFB72FD": (["E2EE-REQ-D2C711B6BB260BFB72FD"], "normative-requirement"),
    "EVID-E2EE-REQ-D70B8B9850E29E082F85": (["E2EE-REQ-D70B8B9850E29E082F85"], "normative-requirement"),
    "EVID-E2EE-REQ-DB900449D8D52DA92117": (["E2EE-REQ-DB900449D8D52DA92117"], "normative-requirement"),
    "EVID-E2EE-REQ-DF1E11F99D8CA9C38917": (["E2EE-REQ-DF1E11F99D8CA9C38917"], "normative-requirement"),
    "EVID-E2EE-REQ-DFF4835BF134E29328E1": (["E2EE-REQ-DFF4835BF134E29328E1"], "normative-requirement"),
    "EVID-E2EE-REQ-E84E3DF2CF6A849CCBA8": (["E2EE-REQ-E84E3DF2CF6A849CCBA8"], "normative-requirement"),
    "EVID-E2EE-REQ-E9D6A931BDD262B08F93": (["E2EE-REQ-E9D6A931BDD262B08F93"], "normative-requirement"),
    "EVID-E2EE-REQ-EC03C8374D88E32F6776": (["E2EE-REQ-EC03C8374D88E32F6776"], "normative-requirement"),
    "EVID-E2EE-REQ-ED359F4450E30FD76278": (["E2EE-REQ-ED359F4450E30FD76278"], "normative-requirement"),
    "EVID-E2EE-REQ-EFECC9F9EB196FD2CF16": (["E2EE-REQ-EFECC9F9EB196FD2CF16"], "normative-requirement"),
    "EVID-E2EE-REQ-F14B7B01F4CFF98A804E": (["E2EE-REQ-F14B7B01F4CFF98A804E"], "normative-requirement"),
    "EVID-E2EE-REQ-F252168A3A468701F674": (["E2EE-REQ-F252168A3A468701F674"], "normative-requirement"),
    "EVID-E2EE-REQ-FDA89A1D5714375C1B4F": (["E2EE-REQ-FDA89A1D5714375C1B4F"], "normative-requirement"),
    "EVID-E2EE-REQ-A119B1A71D9F208380BC": (["E2EE-REQ-A119B1A71D9F208380BC"], "normative-requirement"),
    "EVID-E2EE-REQ-D8D8C1DBDAE5F09E95FD": (["E2EE-REQ-D8D8C1DBDAE5F09E95FD"], "normative-requirement"),
    "EVID-ARCH-PRV-03": (["ARCH-PRV-03"], "normative-requirement"),
    "EVID-ARCH-REQ-09CFFBA54F24F91ED37D": (["ARCH-REQ-09CFFBA54F24F91ED37D"], "normative-requirement"),
    "EVID-ARCH-STA-05": (["ARCH-STA-05"], "normative-requirement"),
    "EVID-ARCH-STA-09": (["ARCH-STA-09"], "normative-requirement"),
}

# Evidence bound to a normative sentence a later revision removed. The
# binding stays so every checkpoint recorded under the earlier text keeps
# validating; a retired entry never counts toward a closure and no new
# manifest may cite it.
RETIRED_BINDINGS = {
    # Section 7.5 padding moved from the MLS padding field to the
    # application content on 2026-09-04 (Stage 08 checkpoint 52c7ccb).
    "EVID-E2EE-REQ-58217F311021E979779A": (["E2EE-REQ-58217F311021E979779A"], "normative-requirement"),
}
REVIEWED_BINDINGS = STAGE_BINDINGS | NORMATIVE_BINDINGS | RETIRED_BINDINGS
TOP_FIELDS = {
    "schema_version",
    "manifest_id",
    "source_commit",
    "source_sha256",
    "lock_sha256",
    "entries",
}
ENTRY_FIELDS = {
    "evidence_id",
    "claim_ids",
    "command",
    "tool",
    "source_commit",
    "source_sha256",
    "lock_sha256",
    "target",
    "features",
    "started_at",
    "ended_at",
    "result",
    "artifact",
    "limitations",
}
ENTRY_V2_FIELDS = ENTRY_FIELDS | {
    "toolchain_policy_sha256",
    "toolchain",
}
TOOL_FIELDS = {"name", "version"}
TOOLCHAIN_FIELDS = {"name", "argv", "version"}
TOOLCHAIN_POLICY_FIELDS = {"name", "first_stage", "argv", "version"}
TOOLCHAIN_POLICY_TOP_FIELDS = {
    "schema_version",
    "rust",
    "cargo_deny",
    "cargo_audit",
    "cargo_llvm_cov",
    "checkout_action_commit",
    "targets",
    "branch_coverage_instrumentation",
    "limitations",
    "tool",
}
ARTIFACT_LEGACY_FIELDS = {"label", "sha256"}
ARTIFACT_PROVENANCE_FIELDS = {"label", "sha256", "path"}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MANIFEST_ID_RE = re.compile(r"EVID-MANIFEST-[A-Z0-9][A-Z0-9_-]{0,63}")
EVIDENCE_ID_RE = re.compile(r"EVID-[A-Z0-9][A-Z0-9_-]{2,127}")
CLAIM_ID_RE = re.compile(r"(?:S\d{2}-(?:\d{3}|900)|(?:ARCH|E2EE)-[A-Z0-9-]+)")
TARGET_RE = re.compile(r"[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_.-]+")
FEATURE_RE = re.compile(r"[A-Za-z0-9_+.-]{1,128}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")
ARTIFACT_PATH_RE = re.compile(
    r"conformance/evidence/artifacts/[A-Za-z0-9][A-Za-z0-9_./-]{0,511}"
)
CLOSABLE_STAGES = frozenset(range(10))
REVIEWED_EVIDENCE_TARGETS = (
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)
REVIEWED_EVIDENCE_FEATURES = ("all-features",)
STAGE_NAMES = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
}
RUN_ARTIFACT_FIELDS = {
    "schema_version",
    "gate",
    "gate_manifest_sha256",
    "argv",
    "tool",
    "source_commit",
    "source_sha256",
    "lock_sha256",
    "target",
    "features",
    "started_at",
    "ended_at",
    "result",
    "exit_code",
    "command_results",
    "evidence",
}
RUN_ARTIFACT_V2_FIELDS = RUN_ARTIFACT_FIELDS | {
    "toolchain_policy_sha256",
    "toolchain",
    "limitations",
}
RUN_COMMAND_FIELDS = {
    "argv",
    "environment",
    "started_at",
    "ended_at",
    "exit_code",
}
RUN_EVIDENCE_FIELDS = {"evidence_id", "kind"}
RUN_ARTIFACT_MAX_BYTES = 4 * 1024 * 1024
RUN_GATE_ENVIRONMENT = {"RUSTC_BOOTSTRAP"}
TOOLCHAIN_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
TOOLCHAIN_MAX_TOOLS = 32


class EvidenceError(ValueError):
    """An evidence schema or manifest validation failure."""


def load_json(path: Path) -> dict[str, object]:
    """Load one JSON object with duplicate-key rejection."""
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML document."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error


def validate_catalog(root: Path) -> dict[str, list[str]]:
    """Validate stage and normative requirement evidence bindings."""
    catalog = load_toml(root / CATALOG_PATH)
    schema_version = catalog.get("schema_version")
    if (
        set(catalog) != {"schema_version", "evidence"}
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise EvidenceError("evidence catalog has an invalid top-level schema")
    raw_entries = catalog.get("evidence")
    if not isinstance(raw_entries, list):
        raise EvidenceError("evidence catalog entries must be an array")

    catalog_records: dict[str, tuple[list[str], str]] = {}
    for index, record in enumerate(raw_entries):
        if not isinstance(record, dict) or set(record) != {"id", "claim_ids", "kind"}:
            raise EvidenceError(f"catalog record {index} has invalid fields")
        evidence_id = record.get("id")
        claim_ids = record.get("claim_ids")
        kind = record.get("kind")
        if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
            raise EvidenceError(f"catalog record {index} has an invalid evidence ID")
        if evidence_id in catalog_records:
            raise EvidenceError(f"duplicate catalog evidence ID: {evidence_id}")
        if (
            not isinstance(claim_ids, list)
            or not claim_ids
            or claim_ids != sorted(set(map(str, claim_ids)))
            or any(
                not isinstance(claim, str) or CLAIM_ID_RE.fullmatch(claim) is None
                for claim in claim_ids
            )
        ):
            raise EvidenceError(f"catalog record {evidence_id} has invalid claims")
        if not isinstance(kind, str) or not kind:
            raise EvidenceError(f"catalog record {evidence_id} has an invalid kind")
        catalog_records[evidence_id] = (claim_ids, kind)

    actual_stage_records = {
        evidence_id: record
        for evidence_id, record in catalog_records.items()
        if evidence_id in STAGE_BINDINGS
    }
    if actual_stage_records != STAGE_BINDINGS:
        raise EvidenceError("stage evidence catalog is missing, stale, or differently bound")

    ledger = load_toml(root / LEDGER_PATH)
    raw_requirements = ledger.get("requirement")
    if not isinstance(raw_requirements, list):
        raise EvidenceError("requirement ledger has no requirement records")
    requirement_records: dict[str, tuple[str, str]] = {}
    for record in raw_requirements:
        if not isinstance(record, dict):
            raise EvidenceError("requirement ledger contains a non-table record")
        identifier = record.get("id")
        evidence_ids = record.get("evidence_ids")
        status = record.get("status")
        if (
            not isinstance(identifier, str)
            or CLAIM_ID_RE.fullmatch(identifier) is None
            or not isinstance(evidence_ids, list)
            or not evidence_ids
            or status not in {"implemented", "unimplemented"}
        ):
            raise EvidenceError("requirement ledger contains an unbound record")
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
                raise EvidenceError(f"requirement {identifier} has an invalid evidence ID")
            if evidence_id in requirement_records or evidence_id in STAGE_BINDINGS:
                raise EvidenceError(f"duplicate evidence binding: {evidence_id}")
            requirement_records[evidence_id] = (identifier, status)

    for evidence_id, (claims, kind) in catalog_records.items():
        if evidence_id in STAGE_BINDINGS or evidence_id in RETIRED_BINDINGS:
            continue
        requirement = requirement_records.get(evidence_id)
        if requirement is None:
            raise EvidenceError(f"catalog contains unrelated evidence ID: {evidence_id}")
        identifier, status = requirement
        if status != "implemented":
            raise EvidenceError(
                f"unimplemented requirement {identifier} must not have closing catalog evidence"
            )
        if claims != [identifier]:
            raise EvidenceError(
                f"normative evidence {evidence_id} must claim only {identifier}"
            )
        if kind != "normative-requirement":
            raise EvidenceError(
                f"normative evidence {evidence_id} must use kind normative-requirement"
            )

    for evidence_id, (identifier, status) in requirement_records.items():
        if status == "implemented" and evidence_id not in catalog_records:
            raise EvidenceError(
                f"implemented requirement {identifier} lacks reviewed catalog evidence {evidence_id}"
            )

    if catalog_records != REVIEWED_BINDINGS:
        raise EvidenceError("reviewed evidence catalog is missing, stale, or differently bound")

    bindings = {
        evidence_id: claims
        for evidence_id, (claims, _kind) in catalog_records.items()
    }
    return bindings


def validate_schema(root: Path) -> None:
    """Ensure the published JSON Schema describes the enforced closed shape."""
    schema_path = root / SCHEMA_PATH
    if hashlib.sha256(schema_path.read_bytes()).hexdigest() != SCHEMA_SHA256:
        raise EvidenceError("evidence schema bytes differ from the reviewed closed schema")
    schema = load_json(schema_path)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise EvidenceError("evidence schema must use JSON Schema draft 2020-12")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise EvidenceError("evidence schema top level must be a closed object")
    if set(schema.get("required", [])) != TOP_FIELDS:
        raise EvidenceError("evidence schema top-level required fields are stale")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise EvidenceError("evidence schema top level has no properties")
    version = properties.get("schema_version")
    if not isinstance(version, dict) or version.get("enum") != [1, 2]:
        raise EvidenceError("evidence schema versions are stale")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise EvidenceError("evidence schema has no definitions")
    for name in ("evidence-v1", "evidence-v2"):
        evidence = definitions.get(name)
        if not isinstance(evidence, dict):
            raise EvidenceError(f"evidence schema has no {name} definition")
        if evidence.get("unevaluatedProperties") is not False:
            raise EvidenceError(f"{name} entries must be closed objects")
    common = definitions.get("evidence-common")
    if not isinstance(common, dict):
        raise EvidenceError("evidence schema has no common entry definition")
    if set(common.get("required", [])) != ENTRY_FIELDS:
        raise EvidenceError("evidence schema version 1 required fields are stale")
    common_properties = common.get("properties")
    if not isinstance(common_properties, dict):
        raise EvidenceError("evidence schema common entry has no properties")
    artifact = common_properties.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("additionalProperties") is not False:
        raise EvidenceError("evidence schema artifact must be a closed object")
    artifact_properties = artifact.get("properties")
    if not isinstance(artifact_properties, dict) or set(artifact_properties) != {
        "label",
        "sha256",
        "path",
    }:
        raise EvidenceError("evidence schema artifact provenance fields are stale")
    v2_extension = definitions.get("evidence-v2-extension")
    if not isinstance(v2_extension, dict):
        raise EvidenceError("evidence schema has no version 2 extension")
    if set(v2_extension.get("required", [])) != ENTRY_V2_FIELDS - ENTRY_FIELDS:
        raise EvidenceError("evidence schema version 2 required fields are stale")


def git_environment(inherited: Mapping[str, str]) -> dict[str, str]:
    """Return process state that cannot redirect or rewrite Git object reads."""
    environment = {
        name: value for name, value in inherited.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def git_bytes(root: Path, arguments: list[str], label: str) -> bytes:
    """Run one Git object lookup and return its raw standard output."""
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=git_environment(os.environ),
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise EvidenceError(f"cannot execute Git for {label}: {error}") from error
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"Git lookup failed for {label}: {details}")
    return completed.stdout


def require_complete_history(root: Path) -> None:
    """Reject shallow history before making ancestry claims."""
    shallow = git_bytes(
        root,
        ["rev-parse", "--is-shallow-repository"],
        "repository history",
    ).strip()
    if shallow != b"false":
        if shallow == b"true":
            raise EvidenceError("evidence closure requires complete Git history")
        raise EvidenceError("Git returned an invalid shallow-repository state")


def validate_index_bytes(
    root: Path,
    relative: str,
    expected_hash: str,
    mismatch: str,
    *,
    expected_mode: str = REGULAR_INDEX_MODE,
) -> None:
    """Require one regular stage-zero index entry with the expected blob and mode."""
    raw_entries = git_bytes(
        root,
        ["ls-files", "--stage", "-z", "--", relative],
        f"{relative} index entry",
    )
    entries = [entry for entry in raw_entries.split(b"\0") if entry]
    if len(entries) != 1:
        raise EvidenceError(f"{relative} has no unique Git index entry")
    try:
        metadata, indexed_path = entries[0].split(b"\t", 1)
        raw_mode, raw_object_id, raw_stage = metadata.split(b" ", 2)
        mode = raw_mode.decode("ascii")
        object_id = raw_object_id.decode("ascii")
        stage = int(raw_stage.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise EvidenceError(f"{relative} has a malformed Git index entry") from error
    if indexed_path != os.fsencode(relative):
        raise EvidenceError(f"{relative} resolved to an unexpected Git index path")
    if stage != 0:
        raise EvidenceError(f"{relative} has a nonzero Git index stage")
    if mode != expected_mode:
        raise EvidenceError(
            f"{relative} has Git index mode {mode}; expected {expected_mode}"
        )
    tracked_bytes = git_bytes(
        root,
        ["cat-file", "blob", object_id],
        f"{relative} in the Git index",
    )
    if hashlib.sha256(tracked_bytes).hexdigest() != expected_hash:
        raise EvidenceError(mismatch)


def commit_blob(root: Path, source_commit: str, path: str) -> bytes:
    """Read one blob from an exact source commit."""
    return git_bytes(root, ["cat-file", "blob", f"{source_commit}:{path}"], path)


def commit_blob_sha256(root: Path, source_commit: str, path: str) -> str:
    """Hash one blob from an exact source commit."""
    return hashlib.sha256(commit_blob(root, source_commit, path)).hexdigest()


def canonical_source_sha256(root: Path, source_commit: str) -> str:
    """Hash tracked blobs and modes from one commit with explicit framing."""
    require_complete_history(root)
    git_bytes(root, ["cat-file", "-e", f"{source_commit}^{{commit}}"], "source commit")
    git_bytes(
        root,
        ["merge-base", "--is-ancestor", source_commit, "HEAD"],
        "source commit ancestry",
    )
    tree = git_bytes(
        root,
        ["ls-tree", "-rz", "--full-tree", source_commit],
        "source tree",
    )
    records: list[tuple[bytes, bytes, bytes]] = []
    for raw_record in tree.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, path = raw_record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
        except ValueError as error:
            raise EvidenceError("Git source tree contains a malformed entry") from error
        if path.startswith(b"conformance/evidence/") and path.endswith(b".json"):
            continue
        if kind != b"blob":
            display_path = path.decode("utf-8", errors="replace")
            raise EvidenceError(f"Git source tree contains unsupported entry {display_path!r}")
        records.append((path, mode, object_id))

    digest = hashlib.sha256()
    for path, mode, object_id in sorted(records):
        content = git_bytes(
            root,
            ["cat-file", "blob", object_id.decode("ascii")],
            path.decode("utf-8", errors="replace"),
        )
        for field in (mode, path, content):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def require_string(
    value: object,
    label: str,
    *,
    minimum: int = 1,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    """Validate and return one bounded string."""
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise EvidenceError(f"{label} must be a string of {minimum}..{maximum} characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} has an invalid format")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    """Parse one canonical UTC evidence timestamp."""
    text = require_string(value, label, maximum=40, pattern=TIMESTAMP_RE)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError(f"{label} must be UTC")
    return parsed


def validate_hash(value: object, label: str) -> str:
    """Validate one lowercase SHA-256 value."""
    return require_string(value, label, minimum=64, maximum=64, pattern=SHA256_RE)


def validate_toolchain(
    value: object,
    label: str,
) -> list[dict[str, object]]:
    """Validate one closed, ordered toolchain identity list."""
    if not isinstance(value, list) or not value or len(value) > TOOLCHAIN_MAX_TOOLS:
        raise EvidenceError(
            f"{label} must be a nonempty array of at most {TOOLCHAIN_MAX_TOOLS} tools"
        )
    tools: list[dict[str, object]] = []
    names: set[str] = set()
    argument_vectors: set[tuple[str, ...]] = set()
    for index, raw_tool in enumerate(value):
        tool_label = f"{label}[{index}]"
        if not isinstance(raw_tool, dict) or set(raw_tool) != TOOLCHAIN_FIELDS:
            raise EvidenceError(f"{tool_label} has invalid fields")
        name = require_string(
            raw_tool.get("name"),
            f"{tool_label}.name",
            maximum=64,
            pattern=TOOLCHAIN_NAME_RE,
        )
        argv = raw_tool.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 32
            or any(
                not isinstance(argument, str) or not argument or len(argument) > 512
                for argument in argv
            )
        ):
            raise EvidenceError(
                f"{tool_label}.argv must contain 1..32 bounded nonempty strings"
            )
        version = require_string(
            raw_tool.get("version"),
            f"{tool_label}.version",
            maximum=512,
        )
        argv_key = tuple(argv)
        if name in names:
            raise EvidenceError(f"{label} contains duplicate tool name {name!r}")
        if argv_key in argument_vectors:
            raise EvidenceError(f"{label} contains duplicate tool probe argv")
        names.add(name)
        argument_vectors.add(argv_key)
        tools.append({"name": name, "argv": list(argv), "version": version})
    return tools


def validate_limitations(value: object, label: str, *, required: bool) -> list[str]:
    """Validate bounded, unique limitations and optionally require disclosure."""
    if not isinstance(value, list) or len(value) > 64 or (required and not value):
        qualifier = "a nonempty" if required else "an"
        raise EvidenceError(f"{label} must be {qualifier} array of at most 64 items")
    limitations: list[str] = []
    for limitation in value:
        limitations.append(require_string(limitation, label, maximum=2048))
    if len(limitations) != len(set(limitations)):
        raise EvidenceError(f"{label} contains a duplicate")
    return limitations


def parse_toolchain_policy(
    policy_bytes: bytes,
    stage: int,
    *,
    label: str,
) -> tuple[str, list[dict[str, object]], list[str]]:
    """Parse one closed toolchain policy and select the requested stage profile."""
    if stage not in CLOSABLE_STAGES:
        raise EvidenceError("toolchain profiles currently cover only Stages 00 through 09")
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()
    try:
        policy = tomllib.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"{label} cannot be read: {error}") from error
    schema_version = policy.get("schema_version")
    if (
        set(policy) != TOOLCHAIN_POLICY_TOP_FIELDS
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise EvidenceError(f"{label} has an invalid top-level schema")
    require_string(policy.get("rust"), f"{label} rust version", maximum=64)
    require_string(policy.get("cargo_deny"), f"{label} cargo-deny version", maximum=64)
    require_string(policy.get("cargo_audit"), f"{label} cargo-audit version", maximum=64)
    require_string(
        policy.get("cargo_llvm_cov"),
        f"{label} cargo-llvm-cov version",
        maximum=64,
    )
    require_string(
        policy.get("checkout_action_commit"),
        f"{label} checkout action commit",
        minimum=40,
        maximum=40,
        pattern=COMMIT_RE,
    )
    targets = policy.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or targets != sorted(set(map(str, targets)))
        or any(
            not isinstance(target, str) or TARGET_RE.fullmatch(target) is None
            for target in targets
        )
    ):
        raise EvidenceError(f"{label} targets must be a sorted unique target list")
    if tuple(targets) != REVIEWED_EVIDENCE_TARGETS:
        raise EvidenceError(f"{label} targets differ from the reviewed conforming hosts")
    require_string(
        policy.get("branch_coverage_instrumentation"),
        f"{label} branch coverage policy",
        maximum=512,
    )
    limitations = validate_limitations(
        policy.get("limitations"),
        f"{label} limitations",
        required=True,
    )
    raw_tools = policy.get("tool")
    if (
        not isinstance(raw_tools, list)
        or not raw_tools
        or len(raw_tools) > TOOLCHAIN_MAX_TOOLS
    ):
        raise EvidenceError(
            f"{label} tools must be a nonempty array of at most {TOOLCHAIN_MAX_TOOLS} items"
        )

    selected: list[dict[str, object]] = []
    names: set[str] = set()
    argument_vectors: set[tuple[str, ...]] = set()
    previous_first_stage = -1
    for index, raw_tool in enumerate(raw_tools):
        tool_label = f"{label} tool {index}"
        if not isinstance(raw_tool, dict) or set(raw_tool) != TOOLCHAIN_POLICY_FIELDS:
            raise EvidenceError(f"{tool_label} has invalid fields")
        first_stage = raw_tool.get("first_stage")
        if (
            type(first_stage) is not int
            or first_stage not in CLOSABLE_STAGES
            or first_stage < previous_first_stage
        ):
            raise EvidenceError(
                f"{tool_label}.first_stage must be ordered within Stages 00 through 09"
            )
        previous_first_stage = first_stage
        normalized = validate_toolchain(
            [
                {
                    "name": raw_tool.get("name"),
                    "argv": raw_tool.get("argv"),
                    "version": raw_tool.get("version"),
                }
            ],
            tool_label,
        )[0]
        name = str(normalized["name"])
        argv_key = tuple(str(argument) for argument in normalized["argv"])
        if name in names:
            raise EvidenceError(f"{label} contains duplicate tool name {name!r}")
        if argv_key in argument_vectors:
            raise EvidenceError(f"{label} contains duplicate tool probe argv")
        names.add(name)
        argument_vectors.add(argv_key)
        if first_stage <= stage:
            selected.append(normalized)
    if not selected:
        raise EvidenceError(f"{label} selects no tools for Stage {stage:02d}")
    if policy_hash != TOOLCHAIN_POLICY_SHA256:
        raise EvidenceError(f"{label} differs from the reviewed closed toolchain policy")
    return policy_hash, selected, limitations


def load_toolchain_policy(
    root: Path,
    stage: int,
) -> tuple[str, list[dict[str, object]], list[str]]:
    """Load the indexed current toolchain profile for a stage gate run."""
    path = root / TOOLCHAIN_POLICY_PATH
    try:
        policy_bytes = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {TOOLCHAIN_POLICY_PATH}: {error}") from error
    policy_hash, tools, limitations = parse_toolchain_policy(
        policy_bytes,
        stage,
        label="toolchain policy",
    )
    validate_index_bytes(
        root,
        TOOLCHAIN_POLICY_PATH,
        policy_hash,
        "current toolchain policy differs from its Git index bytes",
    )
    return policy_hash, tools, limitations


def source_toolchain_policy(
    root: Path,
    stage: int,
    source_commit: str,
) -> tuple[str, list[dict[str, object]], list[str]]:
    """Return the exact committed tool profile and require current-policy parity."""
    policy_bytes = commit_blob(root, source_commit, TOOLCHAIN_POLICY_PATH)
    policy_hash, tools, limitations = parse_toolchain_policy(
        policy_bytes,
        stage,
        label="source toolchain policy",
    )
    current_hash, _current_tools, _current_limitations = load_toolchain_policy(root, stage)
    if current_hash != policy_hash:
        raise EvidenceError("source toolchain policy differs from the current closure policy")
    return policy_hash, tools, limitations


def validate_artifact(
    root: Path,
    artifact: object,
    label: str,
    *,
    require_provenance: bool,
) -> Path | None:
    """Validate an artifact record and, when present, its checked-in bytes."""
    if not isinstance(artifact, dict) or frozenset(artifact) not in {
        frozenset(ARTIFACT_LEGACY_FIELDS),
        frozenset(ARTIFACT_PROVENANCE_FIELDS),
    }:
        raise EvidenceError(
            f"{label} must contain label and sha256, with an optional provenance path"
        )
    require_string(artifact.get("label"), f"{label}.label", maximum=256)
    expected_hash = validate_hash(artifact.get("sha256"), f"{label}.sha256")
    path_value = artifact.get("path")
    if path_value is None:
        if require_provenance:
            raise EvidenceError(f"{label} has no verifiable provenance path")
        return None

    relative = require_string(
        path_value,
        f"{label}.path",
        maximum=550,
        pattern=ARTIFACT_PATH_RE,
    )
    pure_path = PurePosixPath(relative)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise EvidenceError(f"{label}.path must stay inside the evidence artifact directory")
    artifact_root = (root / "conformance/evidence/artifacts").resolve()
    candidate = root.joinpath(*pure_path.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise EvidenceError(f"{label}.path cannot be read: {error}") from error
    if not resolved.is_relative_to(artifact_root) or not resolved.is_file():
        raise EvidenceError(f"{label}.path is not a regular evidence artifact")
    cursor = root
    for part in pure_path.parts:
        cursor /= part
        if cursor.is_symlink():
            raise EvidenceError(f"{label}.path may not traverse a symbolic link")
    actual_hash = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise EvidenceError(f"{label}.sha256 does not match the artifact bytes")
    validate_index_bytes(
        root,
        relative,
        expected_hash,
        f"{label}.sha256 does not match the tracked artifact bytes",
    )
    return resolved


def validate_manifest(
    manifest: dict[str, object],
    bindings: dict[str, list[str]],
    *,
    expected_source_hash: str | None = None,
    expected_lock_hash: str | None = None,
    artifact_root: Path | None = None,
) -> None:
    """Validate one complete evidence manifest and all catalog bindings."""
    if set(manifest) != TOP_FIELDS:
        raise EvidenceError("manifest is missing required fields or has unknown fields")
    schema_version = manifest.get("schema_version")
    if type(schema_version) is not int or schema_version not in {1, 2}:
        raise EvidenceError("manifest schema_version must be 1 or 2")
    require_string(manifest.get("manifest_id"), "manifest_id", maximum=78, pattern=MANIFEST_ID_RE)
    source_commit = require_string(
        manifest.get("source_commit"),
        "source_commit",
        minimum=40,
        maximum=40,
        pattern=COMMIT_RE,
    )
    source_hash = validate_hash(manifest.get("source_sha256"), "source_sha256")
    if expected_source_hash is not None and source_hash != expected_source_hash:
        raise EvidenceError("manifest source hash does not match the canonical Git tree")
    lock_hash = validate_hash(manifest.get("lock_sha256"), "lock_sha256")
    if expected_lock_hash is not None and lock_hash != expected_lock_hash:
        raise EvidenceError("manifest lock hash does not match Cargo.lock at its source commit")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("manifest entries must be a nonempty array")

    seen_evidence: set[str] = set()
    manifest_toolchain: list[dict[str, object]] | None = None
    manifest_policy_hash: str | None = None
    manifest_limitations: list[str] | None = None
    for index, raw_entry in enumerate(entries):
        label = f"entries[{index}]"
        expected_entry_fields = ENTRY_FIELDS if schema_version == 1 else ENTRY_V2_FIELDS
        if not isinstance(raw_entry, dict) or set(raw_entry) != expected_entry_fields:
            raise EvidenceError(f"{label} is missing required fields or has unknown fields")
        entry = raw_entry
        evidence_id = require_string(
            entry.get("evidence_id"), f"{label}.evidence_id", maximum=132, pattern=EVIDENCE_ID_RE
        )
        if evidence_id in seen_evidence:
            raise EvidenceError(f"duplicate manifest evidence ID: {evidence_id}")
        seen_evidence.add(evidence_id)
        expected_claims = bindings.get(evidence_id)
        if expected_claims is None:
            raise EvidenceError(f"unbound evidence ID: {evidence_id}")

        claims = entry.get("claim_ids")
        if not isinstance(claims, list) or not claims:
            raise EvidenceError(f"{label}.claim_ids must be a nonempty array")
        if len(claims) != len(set(map(str, claims))):
            raise EvidenceError(f"{label}.claim_ids contains a duplicate")
        for claim in claims:
            require_string(claim, f"{label}.claim_ids", maximum=128, pattern=CLAIM_ID_RE)
        if claims != expected_claims:
            raise EvidenceError(f"{evidence_id} claims do not match its catalog binding")

        require_string(entry.get("command"), f"{label}.command", maximum=4096)
        tool = entry.get("tool")
        if not isinstance(tool, dict) or set(tool) != TOOL_FIELDS:
            raise EvidenceError(f"{label}.tool must contain only name and version")
        require_string(tool.get("name"), f"{label}.tool.name", maximum=128)
        require_string(tool.get("version"), f"{label}.tool.version", maximum=256)

        if entry.get("source_commit") != source_commit:
            raise EvidenceError(f"{label} has a stale source commit")
        entry_source_hash = validate_hash(entry.get("source_sha256"), f"{label}.source_sha256")
        if entry_source_hash != source_hash:
            raise EvidenceError(f"{label} has a stale source hash")
        entry_lock_hash = validate_hash(entry.get("lock_sha256"), f"{label}.lock_sha256")
        if entry_lock_hash != lock_hash:
            raise EvidenceError(f"{label} has a stale lock hash")
        require_string(entry.get("target"), f"{label}.target", maximum=128, pattern=TARGET_RE)

        features = entry.get("features")
        if not isinstance(features, list):
            raise EvidenceError(f"{label}.features must be an array")
        for feature in features:
            require_string(feature, f"{label}.features", maximum=128, pattern=FEATURE_RE)
        if features != sorted(features) or len(features) != len(set(features)):
            raise EvidenceError(f"{label}.features must be sorted and unique")

        started = parse_timestamp(entry.get("started_at"), f"{label}.started_at")
        ended = parse_timestamp(entry.get("ended_at"), f"{label}.ended_at")
        if ended < started:
            raise EvidenceError(f"{label} ended before it started")
        if entry.get("result") not in {"passed", "failed", "not-run"}:
            raise EvidenceError(f"{label}.result has an invalid value")

        artifact = entry.get("artifact")
        if artifact_root is None:
            if not isinstance(artifact, dict) or frozenset(artifact) not in {
                frozenset(ARTIFACT_LEGACY_FIELDS),
                frozenset(ARTIFACT_PROVENANCE_FIELDS),
            }:
                raise EvidenceError(
                    f"{label}.artifact must contain label and sha256, with an optional path"
                )
            require_string(artifact.get("label"), f"{label}.artifact.label", maximum=256)
            validate_hash(artifact.get("sha256"), f"{label}.artifact.sha256")
            if "path" in artifact:
                require_string(
                    artifact.get("path"),
                    f"{label}.artifact.path",
                    maximum=550,
                    pattern=ARTIFACT_PATH_RE,
                )
        else:
            validate_artifact(
                artifact_root,
                artifact,
                f"{label}.artifact",
                require_provenance=False,
            )

        limitations = validate_limitations(
            entry.get("limitations"),
            f"{label}.limitations",
            required=schema_version == 2,
        )
        if schema_version == 2:
            policy_hash = validate_hash(
                entry.get("toolchain_policy_sha256"),
                f"{label}.toolchain_policy_sha256",
            )
            toolchain = validate_toolchain(entry.get("toolchain"), f"{label}.toolchain")
            if manifest_toolchain is None:
                manifest_toolchain = toolchain
                manifest_policy_hash = policy_hash
                manifest_limitations = limitations
            elif (
                toolchain != manifest_toolchain
                or policy_hash != manifest_policy_hash
                or limitations != manifest_limitations
            ):
                raise EvidenceError(
                    "schema version 2 manifest entries must share one toolchain policy"
                )


def validate(root: Path) -> tuple[int, int]:
    """Validate schema, catalogs, the example, and every checked-in manifest."""
    validate_schema(root)
    bindings = validate_catalog(root)
    example = load_json(root / EXAMPLE_PATH)
    validate_manifest(example, bindings)
    manifest_paths = sorted((root / "conformance/evidence").glob("*.json"))
    entry_count = len(example["entries"])  # type: ignore[arg-type]
    for path in manifest_paths:
        relative = path.relative_to(root).as_posix()
        validate_index_bytes(
            root,
            relative,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            f"{relative} bytes differ from the Git index",
        )
        manifest = load_json(path)
        validate_manifest(manifest, bindings)
        source_commit = str(manifest["source_commit"])
        source_hash = canonical_source_sha256(root, source_commit)
        lock_hash = commit_blob_sha256(root, source_commit, "Cargo.lock")
        validate_manifest(
            manifest,
            bindings,
            expected_source_hash=source_hash,
            expected_lock_hash=lock_hash,
            artifact_root=root,
        )
        entry_count += len(manifest["entries"])  # type: ignore[arg-type]
    return len(bindings), entry_count


# Tasks a stage may close around because their completion is outside the
# implementing team's hands. Each entry names the committed record that must
# carry the task with the state ``blocked-external``; the recorded gate and
# the closure manifest then cover the exact source commit with that task
# open, and nothing else may be open.
EXTERNALLY_BLOCKED_TASKS: dict[int, tuple[str, str]] = {
    8: ("S08-039", "conformance/stage-eight-e2ee-profile.toml"),
}


def externally_blocked_tasks(root: Path, stage: int, source_commit: str) -> set[str]:
    """Return the tasks the committed stage record declares externally blocked."""
    blocked = EXTERNALLY_BLOCKED_TASKS.get(stage)
    if blocked is None:
        return set()
    task, relative = blocked
    try:
        record = tomllib.loads(commit_blob(root, source_commit, relative).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"stage record {relative} is unreadable: {error}") from error
    review = record.get("review")
    if not isinstance(review, dict) or review.get("task") != task:
        raise EvidenceError(f"stage record {relative} does not name blocked task {task}")
    if review.get("state") != "blocked-external":
        raise EvidenceError(f"stage record {relative} does not record {task} as blocked-external")
    return {task}


def required_stage_evidence_ids_from_data(
    stage: int,
    records: object,
    states: dict[str, bool],
    blocked: frozenset[str] = frozenset(),
) -> set[str]:
    """Return the required IDs after validating one source requirement ledger."""
    prefix = f"S{stage:02d}-"
    stage_tasks = {
        claim
        for claims, _kind in STAGE_BINDINGS.values()
        for claim in claims
        if claim.startswith(prefix)
    }
    roadmap_stage_tasks = {task for task in states if task.startswith(prefix)}
    unknown_tasks = sorted(stage_tasks - set(states))
    if unknown_tasks:
        raise EvidenceError(
            "source roadmap is missing Stage "
            f"{stage:02d} tasks: {', '.join(unknown_tasks)}"
        )
    unbound_tasks = sorted(roadmap_stage_tasks - stage_tasks)
    if unbound_tasks:
        raise EvidenceError(
            f"Stage {stage:02d} source roadmap has tasks without evidence bindings: "
            + ", ".join(unbound_tasks)
        )
    gate_task = f"{prefix}900"
    if not states[gate_task]:
        raise EvidenceError(f"Stage {stage:02d} source roadmap gate {gate_task} is open")
    incomplete_tasks = sorted(
        task
        for task in stage_tasks
        if not task.endswith("-900") and not states[task] and task not in blocked
    )
    if incomplete_tasks:
        raise EvidenceError(
            f"Stage {stage:02d} source roadmap has incomplete implementation tasks: "
            + ", ".join(incomplete_tasks)
        )

    required = {
        evidence_id
        for evidence_id, (claims, _kind) in STAGE_BINDINGS.items()
        if any(claim.startswith(prefix) for claim in claims)
    }
    if not isinstance(records, list):
        raise EvidenceError("source requirement ledger has no requirement records")
    incomplete: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            raise EvidenceError("source requirement ledger contains a non-table record")
        tasks = record.get("task_ids")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(tasks, list) or not isinstance(evidence_ids, list):
            raise EvidenceError("source requirement ledger contains an invalid binding")
        if not any(isinstance(task, str) and task.startswith(prefix) for task in tasks):
            continue
        if record.get("status") != "implemented":
            incomplete.append(str(record.get("id")))
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
                raise EvidenceError("source requirement ledger has an invalid evidence ID")
            required.add(evidence_id)
    if incomplete:
        raise EvidenceError(
            f"Stage {stage:02d} still owns unimplemented requirements: "
            + ", ".join(sorted(incomplete))
        )
    if not required:
        raise EvidenceError(f"Stage {stage:02d} has no required evidence bindings")
    return required


def required_stage_evidence_ids(
    root: Path,
    stage: int,
    source_commit: str,
) -> set[str]:
    """Validate one source ledger and return every ID needed for stage closure."""
    source_paths = (
        requirement_ledger.ARCHITECTURE_PATH,
        requirement_ledger.E2EE_PATH,
        requirement_ledger.BINDINGS_PATH,
        requirement_ledger.LEDGER_PATH,
        "TODO.md",
    )
    with tempfile.TemporaryDirectory(prefix="agenc-source-ledger-") as temporary:
        source_root = Path(temporary)
        for relative in source_paths:
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(commit_blob(root, source_commit, relative))
        try:
            requirement_ledger.validate(source_root)
            ledger = requirement_ledger.load_ledger(
                source_root / requirement_ledger.LEDGER_PATH
            )
            states = requirement_ledger.task_states(source_root)
        except requirement_ledger.LedgerError as error:
            raise EvidenceError(
                f"source requirement ledger does not pass the current closure policy: {error}"
            ) from error
        return required_stage_evidence_ids_from_data(
            stage,
            ledger.get("requirement"),
            states,
            frozenset(externally_blocked_tasks(root, stage, source_commit)),
        )


def source_gate_policy(
    root: Path,
    stage: int,
    source_commit: str,
) -> tuple[str, str, str, list[dict[str, object]]]:
    """Return the exact committed runner, gate, and resolved command policy."""
    stage_name = STAGE_NAMES[stage]
    gate_name = f"stage-{stage_name}-implementation"
    gate_bytes = commit_blob(root, source_commit, "conformance/gates.toml")
    gate_hash = hashlib.sha256(gate_bytes).hexdigest()
    current_gate_path = root / "conformance/gates.toml"
    if hashlib.sha256(current_gate_path.read_bytes()).hexdigest() != gate_hash:
        raise EvidenceError("source gate manifest differs from the current closure policy")
    validate_index_bytes(
        root,
        "conformance/gates.toml",
        gate_hash,
        "current gate manifest differs from its Git index bytes",
    )
    try:
        manifest = tomllib.loads(gate_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"source gate manifest cannot be read: {error}") from error
    schema_version = manifest.get("schema_version")
    if (
        set(manifest) != {"schema_version", "gate"}
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise EvidenceError("source gate manifest has an invalid top-level schema")
    gates = manifest.get("gate")
    if not isinstance(gates, dict):
        raise EvidenceError("source gate manifest has no gate table")

    def resolve(name: str, resolving: tuple[str, ...] = ()) -> list[dict[str, object]]:
        if name in resolving:
            raise EvidenceError(f"source gate include cycle reaches {name}")
        gate = gates.get(name)
        if not isinstance(gate, dict) or set(gate) - {"includes", "command"}:
            raise EvidenceError(f"source gate {name!r} is missing or malformed")
        includes = gate.get("includes", [])
        commands = gate.get("command", [])
        if (
            not isinstance(includes, list)
            or any(not isinstance(item, str) or not item for item in includes)
            or len(includes) != len(set(includes))
        ):
            raise EvidenceError(f"source gate {name!r} has invalid includes")
        if not isinstance(commands, list):
            raise EvidenceError(f"source gate {name!r} has invalid commands")
        resolved: list[dict[str, object]] = []
        for included in includes:
            resolved.extend(resolve(included, resolving + (name,)))
        for command in commands:
            if not isinstance(command, dict) or not set(command) <= {"argv", "environment"}:
                raise EvidenceError(f"source gate {name!r} contains a malformed command")
            argv = command.get("argv")
            if (
                not isinstance(argv, list)
                or not argv
                or any(not isinstance(item, str) or not item for item in argv)
            ):
                raise EvidenceError(f"source gate {name!r} contains invalid argv")
            environment = command.get("environment", {})
            if (
                not isinstance(environment, dict)
                or set(environment) - RUN_GATE_ENVIRONMENT
                or any(
                    not isinstance(key, str)
                    or not key
                    or not isinstance(value, str)
                    for key, value in environment.items()
                )
            ):
                raise EvidenceError(f"source gate {name!r} contains invalid environment state")
            resolved.append({"argv": argv, "environment": environment})
        return resolved

    commands = resolve(gate_name)
    if not commands:
        raise EvidenceError(f"source gate {gate_name!r} resolves to no commands")
    runner_hash = commit_blob_sha256(root, source_commit, "scripts/run-gate.py")
    current_runner_hash = hashlib.sha256((root / "scripts/run-gate.py").read_bytes()).hexdigest()
    if runner_hash != current_runner_hash:
        raise EvidenceError("source gate runner differs from the current closure policy")
    validate_index_bytes(
        root,
        "scripts/run-gate.py",
        runner_hash,
        "current gate runner differs from its Git index bytes",
        expected_mode=EXECUTABLE_INDEX_MODE,
    )
    return gate_name, runner_hash, gate_hash, commands


def closure_evidence_inventory(required_ids: set[str]) -> list[dict[str, str]]:
    """Return the exact evidence ID and catalog-kind inventory for closure."""
    inventory: list[dict[str, str]] = []
    for evidence_id in sorted(required_ids):
        binding = REVIEWED_BINDINGS.get(evidence_id)
        if binding is None:
            raise EvidenceError(f"evidence ID lacks a reviewed catalog kind: {evidence_id}")
        kind = binding[1]
        inventory.append({"evidence_id": evidence_id, "kind": kind})
    return inventory


def validate_run_artifact(
    path: Path,
    entries: list[dict[str, object]],
    required_ids: set[str],
    *,
    gate_name: str,
    runner_hash: str,
    gate_hash: str,
    expected_commands: list[dict[str, object]],
    toolchain_policy_hash: str,
    expected_toolchain: list[dict[str, object]],
    expected_limitations: list[str],
    source_commit: str,
    source_hash: str,
    lock_hash: str,
) -> None:
    """Validate one structured, exact-source gate-run artifact."""
    if path.suffix != ".json":
        raise EvidenceError("closure artifact must be a structured JSON gate-run record")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise EvidenceError(f"closure artifact cannot be measured: {error}") from error
    if size > RUN_ARTIFACT_MAX_BYTES:
        raise EvidenceError("closure artifact exceeds the 4 MiB record limit")
    artifact = load_json(path)
    schema_version = artifact.get("schema_version")
    if type(schema_version) is int and schema_version == 1:
        raise EvidenceError(
            "closure artifact schema_version must be 2; version 1 is archive-only"
        )
    if type(schema_version) is not int or schema_version != 2:
        raise EvidenceError("closure artifact schema_version must be 2")
    if set(artifact) != RUN_ARTIFACT_V2_FIELDS:
        raise EvidenceError("closure artifact has invalid gate-run fields")
    if artifact.get("gate") != gate_name:
        raise EvidenceError("closure artifact names the wrong reviewed gate")
    if artifact.get("gate_manifest_sha256") != gate_hash:
        raise EvidenceError("closure artifact is not bound to the committed gate manifest")
    expected_argv = ["python3", "scripts/run-gate.py", gate_name]
    if artifact.get("argv") != expected_argv:
        raise EvidenceError("closure artifact did not invoke the reviewed gate runner")
    expected_tool = {"name": "agenc-ircd-gate-runner", "version": runner_hash}
    if artifact.get("tool") != expected_tool:
        raise EvidenceError("closure artifact is not bound to the committed gate runner")
    if artifact.get("toolchain_policy_sha256") != toolchain_policy_hash:
        raise EvidenceError("closure artifact is not bound to the committed toolchain policy")
    toolchain = validate_toolchain(
        artifact.get("toolchain"),
        "closure artifact toolchain",
    )
    if toolchain != expected_toolchain:
        raise EvidenceError("closure artifact toolchain differs from the reviewed stage profile")
    limitations = validate_limitations(
        artifact.get("limitations"),
        "closure artifact limitations",
        required=True,
    )
    if limitations != expected_limitations:
        raise EvidenceError("closure artifact limitations differ from the reviewed policy")
    if artifact.get("source_commit") != source_commit:
        raise EvidenceError("closure artifact has a stale source commit")
    if artifact.get("source_sha256") != source_hash:
        raise EvidenceError("closure artifact has a stale source hash")
    if artifact.get("lock_sha256") != lock_hash:
        raise EvidenceError("closure artifact has a stale lock hash")

    target = require_string(
        artifact.get("target"),
        "closure artifact target",
        maximum=128,
        pattern=TARGET_RE,
    )
    if target not in REVIEWED_EVIDENCE_TARGETS:
        raise EvidenceError("closure artifact target is not a reviewed conforming host")
    features = artifact.get("features")
    if not isinstance(features, list):
        raise EvidenceError("closure artifact features must be an array")
    for feature in features:
        require_string(
            feature,
            "closure artifact feature",
            maximum=128,
            pattern=FEATURE_RE,
        )
    if features != sorted(features) or len(features) != len(set(features)):
        raise EvidenceError("closure artifact features must be sorted and unique")
    if tuple(features) != REVIEWED_EVIDENCE_FEATURES:
        raise EvidenceError("closure artifact features differ from the reviewed profile")
    started = parse_timestamp(artifact.get("started_at"), "closure artifact started_at")
    ended = parse_timestamp(artifact.get("ended_at"), "closure artifact ended_at")
    if ended < started:
        raise EvidenceError("closure artifact ended before it started")
    if artifact.get("result") != "passed" or type(artifact.get("exit_code")) is not int:
        raise EvidenceError("closure artifact does not record a passed gate run")
    if artifact.get("exit_code") != 0:
        raise EvidenceError("closure artifact does not record a zero gate exit status")

    raw_evidence = artifact.get("evidence")
    if not isinstance(raw_evidence, list):
        raise EvidenceError("closure artifact evidence inventory must be an array")
    evidence: list[dict[str, str]] = []
    for index, item in enumerate(raw_evidence):
        if not isinstance(item, dict) or set(item) != RUN_EVIDENCE_FIELDS:
            raise EvidenceError(f"closure artifact evidence item {index} has invalid fields")
        evidence_id = require_string(
            item.get("evidence_id"),
            f"closure artifact evidence item {index}",
            maximum=132,
            pattern=EVIDENCE_ID_RE,
        )
        kind = require_string(
            item.get("kind"),
            f"closure artifact evidence kind {index}",
            maximum=128,
        )
        evidence.append({"evidence_id": evidence_id, "kind": kind})
    if evidence != closure_evidence_inventory(required_ids):
        raise EvidenceError("closure artifact evidence IDs or catalog kinds are stale")

    raw_results = artifact.get("command_results")
    if not isinstance(raw_results, list) or len(raw_results) != len(expected_commands):
        raise EvidenceError("closure artifact command results are incomplete")
    previous_end = started
    for index, (raw_result, expected) in enumerate(zip(raw_results, expected_commands)):
        if not isinstance(raw_result, dict) or set(raw_result) != RUN_COMMAND_FIELDS:
            raise EvidenceError(f"closure artifact command result {index} has invalid fields")
        if raw_result.get("argv") != expected["argv"]:
            raise EvidenceError(f"closure artifact command result {index} has stale argv")
        if raw_result.get("environment") != expected["environment"]:
            raise EvidenceError(
                f"closure artifact command result {index} has stale environment state"
            )
        command_started = parse_timestamp(
            raw_result.get("started_at"),
            f"closure artifact command result {index} started_at",
        )
        command_ended = parse_timestamp(
            raw_result.get("ended_at"),
            f"closure artifact command result {index} ended_at",
        )
        if (
            command_started < previous_end
            or command_ended < command_started
            or command_ended > ended
        ):
            raise EvidenceError(
                f"closure artifact command result {index} has invalid timing"
            )
        if type(raw_result.get("exit_code")) is not int or raw_result.get("exit_code") != 0:
            raise EvidenceError(
                f"closure artifact command result {index} did not pass"
            )
        previous_end = command_ended

    expected_command = " ".join(expected_argv)
    for evidence_id, entry in sorted(
        ((str(entry["evidence_id"]), entry) for entry in entries),
        key=lambda item: item[0],
    ):
        if entry.get("command") != expected_command:
            raise EvidenceError(f"{evidence_id} did not run the reviewed stage gate")
        if entry.get("tool") != expected_tool:
            raise EvidenceError(f"{evidence_id} names an unreviewed gate tool")
        if entry.get("toolchain_policy_sha256") != toolchain_policy_hash:
            raise EvidenceError(f"{evidence_id} names a stale toolchain policy")
        if entry.get("toolchain") != toolchain:
            raise EvidenceError(f"{evidence_id} has a stale toolchain profile")
        if entry.get("limitations") != limitations:
            raise EvidenceError(f"{evidence_id} has stale limitations")
        if entry.get("target") != target or entry.get("features") != features:
            raise EvidenceError(f"{evidence_id} does not match the gate-run target or features")
        if entry.get("started_at") != artifact.get("started_at"):
            raise EvidenceError(f"{evidence_id} has a stale gate-run start time")
        if entry.get("ended_at") != artifact.get("ended_at"):
            raise EvidenceError(f"{evidence_id} has a stale gate-run end time")


def validate_closure_entries(
    root: Path,
    stage: int,
    entries: list[dict[str, object]],
    required_ids: set[str],
    source_commit: str,
    source_hash: str,
    lock_hash: str,
) -> int:
    """Require one current passed record and one reviewed gate-run artifact."""
    by_id: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        evidence_id = entry.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id in RETIRED_BINDINGS:
            raise EvidenceError(f"closure evidence cites retired binding {evidence_id}")
        if isinstance(evidence_id, str) and evidence_id in required_ids:
            by_id.setdefault(evidence_id, []).append(entry)

    missing = sorted(required_ids - set(by_id))
    if missing:
        raise EvidenceError("closure evidence is missing: " + ", ".join(missing))
    duplicates = sorted(evidence_id for evidence_id, values in by_id.items() if len(values) != 1)
    if duplicates:
        raise EvidenceError("closure evidence is duplicated: " + ", ".join(duplicates))

    nonpassing: list[str] = []
    artifact_paths: set[Path] = set()
    for evidence_id in sorted(required_ids):
        entry = by_id[evidence_id][0]
        if set(entry) != ENTRY_V2_FIELDS:
            raise EvidenceError(
                f"{evidence_id} must use schema version 2 closure fields"
            )
        if entry.get("source_commit") != source_commit:
            raise EvidenceError(f"{evidence_id} is not bound to the requested source commit")
        if entry.get("result") != "passed":
            nonpassing.append(evidence_id)
            continue
        artifact_path = validate_artifact(
            root,
            entry.get("artifact"),
            f"{evidence_id}.artifact",
            require_provenance=True,
        )
        if artifact_path is None:
            raise EvidenceError(f"{evidence_id}.artifact has no verifiable provenance path")
        artifact_paths.add(artifact_path)
    if nonpassing:
        raise EvidenceError(
            "failed or not-run records do not close evidence: " + ", ".join(nonpassing)
        )
    if len(artifact_paths) != 1:
        raise EvidenceError("closure evidence must share one exact stage gate-run artifact")
    gate_name, runner_hash, gate_hash, commands = source_gate_policy(
        root,
        stage,
        source_commit,
    )
    artifact_path = next(iter(artifact_paths))
    expected_artifact_path = (
        root
        / "conformance/evidence/artifacts"
        / f"{gate_name}-{source_commit}.json"
    ).resolve()
    if artifact_path != expected_artifact_path:
        raise EvidenceError("closure evidence artifact path is not canonical for the gate")
    policy_hash, toolchain, limitations = source_toolchain_policy(
        root,
        stage,
        source_commit,
    )
    validate_run_artifact(
        artifact_path,
        [by_id[evidence_id][0] for evidence_id in sorted(required_ids)],
        required_ids,
        gate_name=gate_name,
        runner_hash=runner_hash,
        gate_hash=gate_hash,
        expected_commands=commands,
        toolchain_policy_hash=policy_hash,
        expected_toolchain=toolchain,
        expected_limitations=limitations,
        source_commit=source_commit,
        source_hash=source_hash,
        lock_hash=lock_hash,
    )
    return len(required_ids)


def validate_closure(root: Path, stage: int, source_commit: str) -> tuple[int, int]:
    """Validate exact-revision evidence needed to close one stage."""
    if stage not in CLOSABLE_STAGES:
        raise EvidenceError("closure evidence catalogs currently cover only Stages 00 through 09")
    if COMMIT_RE.fullmatch(source_commit) is None:
        raise EvidenceError("closure source commit must be an exact lowercase 40-character Git ID")
    validate(root)
    bindings = validate_catalog(root)
    source_hash = canonical_source_sha256(root, source_commit)
    lock_hash = commit_blob_sha256(root, source_commit, "Cargo.lock")
    required_ids = required_stage_evidence_ids(root, stage, source_commit)
    current_entries: list[dict[str, object]] = []
    current_manifests = 0
    legacy_manifests = 0
    for path in sorted((root / "conformance/evidence").glob("*.json")):
        manifest = load_json(path)
        if manifest.get("source_commit") != source_commit:
            continue
        validate_manifest(
            manifest,
            bindings,
            expected_source_hash=source_hash,
            expected_lock_hash=lock_hash,
            artifact_root=root,
        )
        if manifest.get("schema_version") != 2:
            legacy_manifests += 1
            continue
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            raise EvidenceError(f"{path} has no evidence entries")
        current_entries.extend(entry for entry in entries if isinstance(entry, dict))
        current_manifests += 1
    if current_manifests == 0:
        if legacy_manifests:
            raise EvidenceError(
                "schema version 1 manifests are archive-only and cannot close a stage"
            )
        raise EvidenceError("no evidence manifest is bound to the requested source commit")
    count = validate_closure_entries(
        root,
        stage,
        current_entries,
        required_ids,
        source_commit,
        source_hash,
        lock_hash,
    )
    return count, current_manifests


def expect_rejection(
    label: str,
    manifest: dict[str, object],
    bindings: dict[str, list[str]],
    fragment: str,
) -> None:
    """Require a malformed fixture to reach its intended rejection branch."""
    try:
        validate_manifest(manifest, bindings)
    except EvidenceError as error:
        if fragment not in str(error):
            raise EvidenceError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise EvidenceError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise positive validation and every negative contract category."""
    validate_schema(root)
    bindings = validate_catalog(root)
    valid = load_json(root / EXAMPLE_PATH)
    validate_manifest(valid, bindings)
    cases = 0

    with tempfile.TemporaryDirectory(prefix="agenc-evidence-catalog-test-") as temporary:
        temporary_root = Path(temporary)
        conformance = temporary_root / "conformance"
        conformance.mkdir()
        catalog_text = (root / CATALOG_PATH).read_text(encoding="utf-8")
        (temporary_root / CATALOG_PATH).write_text(
            catalog_text.replace("schema_version = 1", "schema_version = true", 1),
            encoding="utf-8",
        )
        (temporary_root / LEDGER_PATH).write_bytes((root / LEDGER_PATH).read_bytes())
        try:
            validate_catalog(temporary_root)
        except EvidenceError as error:
            if "invalid top-level schema" not in str(error):
                raise EvidenceError(
                    f"self-test 'boolean catalog schema' reached the wrong branch: {error}"
                ) from error
        else:
            raise EvidenceError("self-test 'boolean catalog schema' was accepted")
        cases += 1

    catalog_text = (root / CATALOG_PATH).read_text(encoding="utf-8")
    ledger_bytes = (root / LEDGER_PATH).read_bytes()
    auth_record = """[[evidence]]
id = "EVID-ARCH-AUTH-01"
claim_ids = ["ARCH-AUTH-01"]
kind = "normative-requirement"
"""
    if auth_record not in catalog_text:
        raise EvidenceError("self-test catalog fixture cannot find ARCH-AUTH-01")

    def reject_catalog(label: str, malformed: str, fragment: str) -> None:
        nonlocal cases
        if malformed == catalog_text:
            raise EvidenceError(f"self-test {label!r} did not mutate the catalog")
        with tempfile.TemporaryDirectory(
            prefix="agenc-evidence-catalog-test-"
        ) as temporary:
            temporary_root = Path(temporary)
            conformance = temporary_root / "conformance"
            conformance.mkdir()
            (temporary_root / CATALOG_PATH).write_text(malformed, encoding="utf-8")
            (temporary_root / LEDGER_PATH).write_bytes(ledger_bytes)
            try:
                validate_catalog(temporary_root)
            except EvidenceError as error:
                if fragment not in str(error):
                    raise EvidenceError(
                        f"self-test {label!r} reached the wrong branch: {error}"
                    ) from error
            else:
                raise EvidenceError(f"self-test {label!r} was accepted")
        cases += 1

    reject_catalog(
        "missing normative catalog record",
        catalog_text.replace(auth_record, "", 1),
        "implemented requirement ARCH-AUTH-01 lacks reviewed catalog evidence",
    )
    reject_catalog(
        "unrelated normative claim",
        catalog_text.replace(
            'claim_ids = ["ARCH-AUTH-01"]',
            'claim_ids = ["ARCH-AUTH-04"]',
            1,
        ),
        "must claim only ARCH-AUTH-01",
    )
    reject_catalog(
        "stage claim on normative evidence",
        catalog_text.replace(
            'claim_ids = ["ARCH-AUTH-01"]',
            'claim_ids = ["S04-014"]',
            1,
        ),
        "must claim only ARCH-AUTH-01",
    )
    reject_catalog(
        "wrong normative catalog kind",
        catalog_text.replace(
            auth_record,
            auth_record.replace('kind = "normative-requirement"', 'kind = "stage-gate"'),
            1,
        ),
        "must use kind normative-requirement",
    )
    reject_catalog(
        "unimplemented normative catalog record",
        catalog_text
        + """

[[evidence]]
id = "EVID-ARCH-OPS-01"
claim_ids = ["ARCH-OPS-01"]
kind = "normative-requirement"
""",
        "unimplemented requirement ARCH-OPS-01 must not have closing catalog evidence",
    )
    reject_catalog(
        "unrelated catalog evidence",
        catalog_text
        + """

[[evidence]]
id = "EVID-ARCH-REQ-00000000000000000000"
claim_ids = ["ARCH-REQ-00000000000000000000"]
kind = "normative-requirement"
""",
        "catalog contains unrelated evidence ID",
    )

    try:
        closure_evidence_inventory({"EVID-ARCH-OPS-01"})
    except EvidenceError as error:
        if "lacks a reviewed catalog kind" not in str(error):
            raise EvidenceError(
                "self-test 'generic normative kind fallback' reached the wrong branch: "
                f"{error}"
            ) from error
    else:
        raise EvidenceError("self-test 'generic normative kind fallback' was accepted")
    cases += 1

    policy_text = (root / TOOLCHAIN_POLICY_PATH).read_text(encoding="utf-8")
    stage_zero_policy = parse_toolchain_policy(
        policy_text.encode("utf-8"),
        0,
        label="self-test toolchain policy",
    )
    stage_four_policy = parse_toolchain_policy(
        policy_text.encode("utf-8"),
        4,
        label="self-test toolchain policy",
    )
    if (
        stage_zero_policy[0] != TOOLCHAIN_POLICY_SHA256
        or stage_four_policy[0] != TOOLCHAIN_POLICY_SHA256
        or len(stage_zero_policy[1]) != 12
        or len(stage_four_policy[1]) != 17
        or stage_zero_policy[2] != stage_four_policy[2]
    ):
        raise EvidenceError("self-test toolchain profiles differ from reviewed policy")

    def reject_toolchain_policy(label: str, malformed: str, fragment: str) -> None:
        nonlocal cases
        if malformed == policy_text:
            raise EvidenceError(f"self-test {label!r} did not mutate the toolchain policy")
        try:
            parse_toolchain_policy(
                malformed.encode("utf-8"),
                4,
                label="self-test toolchain policy",
            )
        except EvidenceError as error:
            if fragment not in str(error):
                raise EvidenceError(
                    f"self-test {label!r} reached the wrong branch: {error}"
                ) from error
        else:
            raise EvidenceError(f"self-test {label!r} was accepted")
        cases += 1

    reject_toolchain_policy(
        "boolean toolchain schema",
        policy_text.replace("schema_version = 1", "schema_version = true", 1),
        "invalid top-level schema",
    )
    reject_toolchain_policy(
        "unknown toolchain policy field",
        policy_text.replace(
            "schema_version = 1",
            "schema_version = 1\nunreviewed = true",
            1,
        ),
        "invalid top-level schema",
    )
    reject_toolchain_policy(
        "empty toolchain limitations",
        re.sub(
            r"limitations = \[.*?\]\n\n\[\[tool\]\]",
            "limitations = []\n\n[[tool]]",
            policy_text,
            count=1,
            flags=re.DOTALL,
        ),
        "nonempty array",
    )
    reject_toolchain_policy(
        "duplicate toolchain name",
        policy_text.replace('name = "cargo"', 'name = "rustc"', 1),
        "duplicate tool name",
    )
    reject_toolchain_policy(
        "unordered toolchain stage",
        policy_text.replace("first_stage = 0", "first_stage = 2", 1),
        "first_stage must be ordered",
    )
    reject_toolchain_policy(
        "empty toolchain argv",
        policy_text.replace('argv = ["rustc", "--version"]', "argv = []", 1),
        "argv must contain",
    )
    first_tool_block = re.search(
        r"\[\[tool\]\]\nname = \"rustc\".*?(?=\n\[\[tool\]\])",
        policy_text,
        flags=re.DOTALL,
    )
    if first_tool_block is None:
        raise EvidenceError("self-test cannot find the first reviewed tool")
    reject_toolchain_policy(
        "missing reviewed tool",
        policy_text.replace(first_tool_block.group(0), "", 1),
        "reviewed closed toolchain policy",
    )
    reject_toolchain_policy(
        "substituted reviewed tool version",
        policy_text.replace("cargo-deny 0.20.2", "cargo-deny 0.20.3", 1),
        "reviewed closed toolchain policy",
    )
    reject_toolchain_policy(
        "changed reviewed first stage",
        policy_text.replace(
            'name = "nightly-rustc"\nfirst_stage = 2',
            'name = "nightly-rustc"\nfirst_stage = 1',
            1,
        ),
        "reviewed closed toolchain policy",
    )
    reject_toolchain_policy(
        "changed reviewed limitation",
        policy_text.replace(
            "Command output is not captured.",
            "Command output capture is partial.",
            1,
        ),
        "reviewed closed toolchain policy",
    )

    def reject(label: str, mutation: callable, fragment: str) -> None:  # type: ignore[valid-type]
        nonlocal cases
        malformed = copy.deepcopy(valid)
        mutation(malformed)
        expect_rejection(label, malformed, bindings, fragment)
        cases += 1

    reject(
        "boolean manifest schema",
        lambda value: value.__setitem__("schema_version", True),
        "manifest schema_version must be 1 or 2",
    )
    reject("missing field", lambda value: value.pop("lock_sha256"), "missing required")
    reject(
        "duplicate evidence",
        lambda value: value["entries"].append(copy.deepcopy(value["entries"][0])),  # type: ignore[union-attr,index]
        "duplicate manifest evidence ID",
    )
    reject(
        "unbound evidence",
        lambda value: value["entries"][0].__setitem__("evidence_id", "EVID-UNKNOWN-GATE"),  # type: ignore[index,union-attr]
        "unbound evidence ID",
    )
    reject(
        "wrong claims",
        lambda value: value["entries"][0].__setitem__("claim_ids", ["S00-009"]),  # type: ignore[index,union-attr]
        "claims do not match",
    )
    reject(
        "duplicate claim",
        lambda value: value["entries"][0].__setitem__("claim_ids", ["S00-010", "S00-010"]),  # type: ignore[index,union-attr]
        "contains a duplicate",
    )
    reject(
        "stale commit",
        lambda value: value["entries"][0].__setitem__("source_commit", "1" * 40),  # type: ignore[index,union-attr]
        "stale source commit",
    )
    reject(
        "stale source",
        lambda value: value["entries"][0].__setitem__("source_sha256", "1" * 64),  # type: ignore[index,union-attr]
        "stale source hash",
    )
    reject(
        "stale lock",
        lambda value: value["entries"][0].__setitem__("lock_sha256", "1" * 64),  # type: ignore[index,union-attr]
        "stale lock hash",
    )
    reject(
        "bad target",
        lambda value: value["entries"][0].__setitem__("target", "linux"),  # type: ignore[index,union-attr]
        "target has an invalid format",
    )
    reject(
        "unsorted features",
        lambda value: value["entries"][0].__setitem__("features", ["z", "a"]),  # type: ignore[index,union-attr]
        "sorted and unique",
    )
    reject(
        "mixed-type features",
        lambda value: value["entries"][0].__setitem__(  # type: ignore[index,union-attr]
            "features",
            ["all-features", 1],
        ),
        "features must be a string",
    )
    reject(
        "reverse time",
        lambda value: value["entries"][0].__setitem__("ended_at", "2026-08-23T23:59:59Z"),  # type: ignore[index,union-attr]
        "ended before",
    )
    reject(
        "bad result",
        lambda value: value["entries"][0].__setitem__("result", "unknown"),  # type: ignore[index,union-attr]
        "invalid value",
    )
    reject(
        "bad artifact hash",
        lambda value: value["entries"][0]["artifact"].__setitem__("sha256", "bad"),  # type: ignore[index,union-attr]
        "artifact.sha256 must be",
    )
    reject(
        "empty command",
        lambda value: value["entries"][0].__setitem__("command", ""),  # type: ignore[index,union-attr]
        "command must be",
    )
    reject(
        "empty limitation",
        lambda value: value["entries"][0].__setitem__("limitations", [""]),  # type: ignore[index,union-attr]
        "limitations must be",
    )

    historical_failure = copy.deepcopy(valid)
    historical_failure["entries"][0]["result"] = "failed"  # type: ignore[index]
    validate_manifest(historical_failure, bindings)

    legacy = copy.deepcopy(valid)
    legacy["schema_version"] = 1
    legacy_entry = legacy["entries"][0]  # type: ignore[index]
    legacy_entry.pop("toolchain_policy_sha256")  # type: ignore[union-attr]
    legacy_entry.pop("toolchain")  # type: ignore[union-attr]
    validate_manifest(legacy, bindings)
    empty_version_two_limitations = copy.deepcopy(valid)
    empty_version_two_limitations["entries"][0]["limitations"] = []  # type: ignore[index]
    expect_rejection(
        "empty version 2 limitations",
        empty_version_two_limitations,
        bindings,
        "nonempty array",
    )
    cases += 1

    requirement_ledger.validate(root)
    source_ledger = requirement_ledger.load_ledger(root / requirement_ledger.LEDGER_PATH)
    source_records = source_ledger.get("requirement")
    source_states = requirement_ledger.task_states(root)
    closure_states = dict(source_states)
    closure_states["S00-900"] = True
    required_stage_evidence_ids_from_data(0, source_records, closure_states)

    open_states = dict(source_states)
    open_states["S00-900"] = False
    try:
        required_stage_evidence_ids_from_data(0, source_records, open_states)
    except EvidenceError as error:
        if "source roadmap gate S00-900 is open" not in str(error):
            raise EvidenceError(
                f"self-test 'open source gate' reached the wrong branch: {error}"
            ) from error
    else:
        raise EvidenceError("self-test 'open source gate' was accepted")
    cases += 1

    unbound_states = dict(closure_states)
    unbound_states["S00-777"] = True
    try:
        required_stage_evidence_ids_from_data(0, source_records, unbound_states)
    except EvidenceError as error:
        if "tasks without evidence bindings" not in str(error):
            raise EvidenceError(
                f"self-test 'unbound source task' reached the wrong branch: {error}"
            ) from error
    else:
        raise EvidenceError("self-test 'unbound source task' was accepted")
    cases += 1

    incomplete_states = dict(closure_states)
    incomplete_states["S00-001"] = False
    try:
        required_stage_evidence_ids_from_data(0, source_records, incomplete_states)
    except EvidenceError as error:
        if "incomplete implementation tasks" not in str(error):
            raise EvidenceError(
                f"self-test 'incomplete source task' reached the wrong branch: {error}"
            ) from error
    else:
        raise EvidenceError("self-test 'incomplete source task' was accepted")
    cases += 1

    required_stage_evidence_ids_from_data(
        0, source_records, incomplete_states, frozenset({"S00-001"})
    )
    cases += 1

    try:
        validate_closure(root, 10, "2" * 40)
    except EvidenceError as error:
        if "only Stages 00 through 09" not in str(error):
            raise EvidenceError(
                f"self-test 'unsupported closure stage' reached the wrong branch: {error}"
            ) from error
    else:
        raise EvidenceError("self-test 'unsupported closure stage' was accepted")
    cases += 1

    incomplete_records = copy.deepcopy(source_records)
    if not isinstance(incomplete_records, list):
        raise EvidenceError("self-test source ledger has no requirement records")
    stage_zero_record = next(
        record
        for record in incomplete_records
        if isinstance(record, dict)
        and any(
            isinstance(task, str) and task.startswith("S00-")
            for task in record.get("task_ids", [])
        )
    )
    stage_zero_record["status"] = "unimplemented"
    try:
        required_stage_evidence_ids_from_data(0, incomplete_records, closure_states)
    except EvidenceError as error:
        if "owns unimplemented requirements" not in str(error):
            raise EvidenceError(
                f"self-test 'incomplete source requirement' reached the wrong branch: {error}"
            ) from error
    else:
        raise EvidenceError("self-test 'incomplete source requirement' was accepted")
    cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-git-provenance-test-") as temporary:
        temporary_root = Path(temporary)
        source_path = temporary_root / "source.txt"
        source_path.write_text("original source\n", encoding="utf-8")
        git_bytes(temporary_root, ["init", "--quiet"], "provenance test repository")
        git_bytes(temporary_root, ["add", "--", "source.txt"], "provenance test source")
        author = [
            "-c",
            "user.name=Evidence Self-Test",
            "-c",
            "user.email=evidence@example.invalid",
        ]
        git_bytes(
            temporary_root,
            [*author, "commit", "--quiet", "-m", "Add original source"],
            "provenance test source commit",
        )
        source_commit = git_bytes(
            temporary_root,
            ["rev-parse", "HEAD"],
            "provenance test source commit ID",
        ).decode("ascii").strip()
        original_hash = canonical_source_sha256(temporary_root, source_commit)
        original_blob = commit_blob(temporary_root, source_commit, "source.txt")

        baseline_policy = runpy.run_path(
            str(root / "scripts/check-baseline.py"),
            run_name="agenc_ircd_baseline_policy",
        )
        baseline_blob = baseline_policy.get("frozen_blob")
        baseline_validate_commit = baseline_policy.get("validate_frozen_commit")
        baseline_error = baseline_policy.get("BaselineError")
        if (
            not callable(baseline_blob)
            or not callable(baseline_validate_commit)
            or not isinstance(baseline_error, type)
        ):
            raise EvidenceError("self-test cannot load frozen baseline Git policy")

        empty_tree = git_bytes(
            temporary_root,
            ["hash-object", "-t", "tree", os.devnull],
            "empty replacement tree",
        ).decode("ascii").strip()
        replacement_commit = git_bytes(
            temporary_root,
            [*author, "commit-tree", empty_tree, "-m", "Replacement source"],
            "replacement source commit",
        ).decode("ascii").strip()
        git_bytes(
            temporary_root,
            ["replace", source_commit, replacement_commit],
            "replacement source reference",
        )
        attack_environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("GIT_")
        }
        replaced_read = subprocess.run(
            ["git", "cat-file", "-e", f"{source_commit}:source.txt"],
            cwd=temporary_root,
            env=attack_environment,
            capture_output=True,
            check=False,
        )
        if replaced_read.returncode == 0:
            raise EvidenceError("self-test replacement reference did not alter ordinary Git")
        if commit_blob(temporary_root, source_commit, "source.txt") != original_blob:
            raise EvidenceError("replacement reference changed an evidence source blob")
        if canonical_source_sha256(temporary_root, source_commit) != original_hash:
            raise EvidenceError("replacement reference changed the canonical source hash")
        if baseline_blob(temporary_root, source_commit, "source.txt") != original_blob:
            raise EvidenceError("replacement reference changed a frozen baseline blob")
        git_bytes(
            temporary_root,
            ["replace", "-d", source_commit],
            "replacement source cleanup",
        )
        cases += 1

        git_bytes(
            temporary_root,
            [*author, "commit", "--quiet", "--allow-empty", "-m", "Add descendant"],
            "provenance test descendant",
        )
        descendant_commit = git_bytes(
            temporary_root,
            ["rev-parse", "HEAD"],
            "provenance test descendant ID",
        ).decode("ascii").strip()
        graft_path = temporary_root / ".git/info/grafts"
        graft_path.parent.mkdir(parents=True, exist_ok=True)
        graft_path.write_text(f"{descendant_commit}\n", encoding="ascii")
        grafted_ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", source_commit, descendant_commit],
            cwd=temporary_root,
            env=attack_environment,
            capture_output=True,
            check=False,
        )
        if grafted_ancestry.returncode != 1:
            raise EvidenceError("self-test graft did not alter ordinary Git ancestry")
        git_bytes(
            temporary_root,
            ["merge-base", "--is-ancestor", source_commit, descendant_commit],
            "graft-isolated evidence ancestry",
        )
        baseline_validate_commit(temporary_root, source_commit)
        graft_path.unlink()
        cases += 1

        shallow_path = temporary_root / ".git/shallow"
        shallow_path.write_text(f"{descendant_commit}\n", encoding="ascii")
        try:
            canonical_source_sha256(temporary_root, source_commit)
        except EvidenceError as error:
            if "complete Git history" not in str(error):
                raise EvidenceError(
                    f"self-test 'shallow evidence history' reached the wrong branch: {error}"
                ) from error
        else:
            raise EvidenceError("self-test 'shallow evidence history' was accepted")
        cases += 1
        try:
            baseline_validate_commit(temporary_root, source_commit)
        except baseline_error as error:
            if "complete Git history" not in str(error):
                raise EvidenceError(
                    f"self-test 'shallow baseline history' reached the wrong branch: {error}"
                ) from error
        else:
            raise EvidenceError("self-test 'shallow baseline history' was accepted")
        cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-evidence-self-test-") as temporary:
        temporary_root = Path(temporary)
        runner_path = temporary_root / "scripts/run-gate.py"
        gate_path = temporary_root / "conformance/gates.toml"
        policy_path = temporary_root / TOOLCHAIN_POLICY_PATH
        artifact_directory = temporary_root / "conformance/evidence/artifacts"
        runner_path.parent.mkdir(parents=True)
        gate_path.parent.mkdir(parents=True)
        artifact_directory.mkdir(parents=True)
        runner_path.write_text("# reviewed self-test gate runner\n", encoding="utf-8")
        runner_path.chmod(0o755)
        gate_path.write_text(
            """schema_version = 1

[gate.stage-zero-implementation]

[[gate.stage-zero-implementation.command]]
argv = ["python3", "scripts/check-evidence.py", "check"]
""",
            encoding="utf-8",
        )
        policy_path.write_bytes((root / TOOLCHAIN_POLICY_PATH).read_bytes())
        git_bytes(temporary_root, ["init", "--quiet"], "self-test repository")
        git_bytes(
            temporary_root,
            [
                "-c",
                "user.name=Evidence Self-Test",
                "-c",
                "user.email=evidence@example.invalid",
                "add",
                "--",
                "scripts/run-gate.py",
                "conformance/gates.toml",
                TOOLCHAIN_POLICY_PATH,
            ],
            "self-test source files",
        )
        git_bytes(
            temporary_root,
            [
                "-c",
                "user.name=Evidence Self-Test",
                "-c",
                "user.email=evidence@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "Add self-test gate",
            ],
            "self-test source commit",
        )
        closure_commit = git_bytes(
            temporary_root,
            ["rev-parse", "HEAD"],
            "self-test source commit ID",
        ).decode("ascii").strip()
        closure_id = "EVID-S00-010-MANIFEST-SCHEMA"
        closure_source_hash = "2" * 64
        closure_lock_hash = "3" * 64
        gate_name, runner_hash, gate_hash, commands = source_gate_policy(
            temporary_root,
            0,
            closure_commit,
        )
        artifact_path = artifact_directory / f"{gate_name}-{closure_commit}.json"
        policy_hash, toolchain, limitations = source_toolchain_policy(
            temporary_root,
            0,
            closure_commit,
        )
        _stage_two_hash, stage_two_toolchain, _stage_two_limitations = (
            source_toolchain_policy(temporary_root, 2, closure_commit)
        )
        if len(toolchain) != 12 or len(stage_two_toolchain) != 17:
            raise EvidenceError("self-test toolchain stage profiles are not cumulative")
        run_artifact: dict[str, object] = {
            "schema_version": 2,
            "gate": gate_name,
            "gate_manifest_sha256": gate_hash,
            "toolchain_policy_sha256": policy_hash,
            "toolchain": toolchain,
            "limitations": limitations,
            "argv": ["python3", "scripts/run-gate.py", gate_name],
            "tool": {
                "name": "agenc-ircd-gate-runner",
                "version": runner_hash,
            },
            "source_commit": closure_commit,
            "source_sha256": closure_source_hash,
            "lock_sha256": closure_lock_hash,
            "target": "x86_64-unknown-linux-gnu",
            "features": ["all-features"],
            "started_at": "2026-08-24T00:00:00Z",
            "ended_at": "2026-08-24T00:00:02Z",
            "result": "passed",
            "exit_code": 0,
            "command_results": [
                {
                    "argv": command["argv"],
                    "environment": command["environment"],
                    "started_at": "2026-08-24T00:00:00Z",
                    "ended_at": "2026-08-24T00:00:01Z",
                    "exit_code": 0,
                }
                for command in commands
            ],
            "evidence": closure_evidence_inventory({closure_id}),
        }

        def stage_artifact(payload: dict[str, object], path: Path = artifact_path) -> str:
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            relative = path.relative_to(temporary_root).as_posix()
            git_bytes(
                temporary_root,
                ["add", "--", relative],
                "self-test artifact",
            )
            return hashlib.sha256(path.read_bytes()).hexdigest()

        artifact_hash = stage_artifact(run_artifact)
        closure_entry = copy.deepcopy(valid["entries"][0])  # type: ignore[index]
        closure_entry["command"] = f"python3 scripts/run-gate.py {gate_name}"
        closure_entry["tool"] = {
            "name": "agenc-ircd-gate-runner",
            "version": runner_hash,
        }
        closure_entry["toolchain_policy_sha256"] = policy_hash
        closure_entry["toolchain"] = toolchain
        closure_entry["source_commit"] = closure_commit
        closure_entry["source_sha256"] = closure_source_hash
        closure_entry["lock_sha256"] = closure_lock_hash
        closure_entry["target"] = "x86_64-unknown-linux-gnu"
        closure_entry["features"] = ["all-features"]
        closure_entry["started_at"] = "2026-08-24T00:00:00Z"
        closure_entry["ended_at"] = "2026-08-24T00:00:02Z"
        closure_entry["result"] = "passed"
        closure_entry["limitations"] = limitations
        closure_entry["artifact"] = {
            "label": "closure-test",
            "sha256": artifact_hash,
            "path": (
                "conformance/evidence/artifacts/"
                f"{gate_name}-{closure_commit}.json"
            ),
        }
        validate_closure_entries(
            temporary_root,
            0,
            [closure_entry],
            {closure_id},
            closure_commit,
            closure_source_hash,
            closure_lock_hash,
        )

        def reject_closure(label: str, entries: list[dict[str, object]], fragment: str) -> None:
            nonlocal cases
            try:
                validate_closure_entries(
                    temporary_root,
                    0,
                    entries,
                    {closure_id},
                    closure_commit,
                    closure_source_hash,
                    closure_lock_hash,
                )
            except EvidenceError as error:
                if fragment not in str(error):
                    raise EvidenceError(
                        f"self-test {label!r} reached the wrong branch: {error}"
                    ) from error
            else:
                raise EvidenceError(f"self-test {label!r} was accepted")
            cases += 1

        artifact_relative = artifact_path.relative_to(temporary_root).as_posix()

        def replace_index_mode(relative: str, mode: str) -> None:
            object_id = git_bytes(
                temporary_root,
                ["rev-parse", f":{relative}"],
                "self-test index object ID",
            ).decode("ascii").strip()
            git_bytes(
                temporary_root,
                [
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"{mode},{object_id},{relative}",
                ],
                "self-test index mode",
            )

        replace_index_mode(artifact_relative, "120000")
        reject_closure(
            "symbolic-link artifact index mode",
            [closure_entry],
            "expected 100644",
        )
        stage_artifact(run_artifact)
        replace_index_mode(artifact_relative, "100755")
        reject_closure(
            "executable artifact index mode",
            [closure_entry],
            "expected 100644",
        )
        stage_artifact(run_artifact)

        manifest_mode_path = temporary_root / "conformance/evidence/index-mode.json"
        manifest_mode_path.write_bytes(b"{}\n")
        manifest_mode_relative = manifest_mode_path.relative_to(temporary_root).as_posix()
        git_bytes(
            temporary_root,
            ["add", "--", manifest_mode_relative],
            "self-test manifest index fixture",
        )
        manifest_mode_hash = hashlib.sha256(manifest_mode_path.read_bytes()).hexdigest()

        def reject_manifest_index_mode(label: str, mode: str) -> None:
            nonlocal cases
            replace_index_mode(manifest_mode_relative, mode)
            try:
                validate_index_bytes(
                    temporary_root,
                    manifest_mode_relative,
                    manifest_mode_hash,
                    "self-test manifest bytes differ",
                )
            except EvidenceError as error:
                if "expected 100644" not in str(error):
                    raise EvidenceError(
                        f"self-test {label!r} reached the wrong branch: {error}"
                    ) from error
            else:
                raise EvidenceError(f"self-test {label!r} was accepted")
            git_bytes(
                temporary_root,
                ["add", "--", manifest_mode_relative],
                "restore self-test manifest index fixture",
            )
            cases += 1

        reject_manifest_index_mode("symbolic-link manifest index mode", "120000")
        reject_manifest_index_mode("executable manifest index mode", "100755")

        reject_closure("missing closure evidence", [], "closure evidence is missing")
        failed = copy.deepcopy(closure_entry)
        failed["result"] = "failed"
        reject_closure("failed closure evidence", [failed], "do not close evidence")
        not_run = copy.deepcopy(closure_entry)
        not_run["result"] = "not-run"
        reject_closure("not-run closure evidence", [not_run], "do not close evidence")
        legacy = copy.deepcopy(closure_entry)
        legacy["artifact"].pop("path")  # type: ignore[union-attr]
        reject_closure("legacy closure artifact", [legacy], "no verifiable provenance path")
        tampered = copy.deepcopy(closure_entry)
        tampered["artifact"]["sha256"] = "0" * 64  # type: ignore[index]
        reject_closure("tampered closure artifact", [tampered], "does not match")
        duplicate = [copy.deepcopy(closure_entry), copy.deepcopy(closure_entry)]
        reject_closure("duplicate closure evidence", duplicate, "closure evidence is duplicated")
        stale_commit = copy.deepcopy(closure_entry)
        stale_commit["source_commit"] = "3" * 40
        reject_closure("stale closure source", [stale_commit], "requested source commit")
        traversal = copy.deepcopy(closure_entry)
        traversal["artifact"]["path"] = (  # type: ignore[index]
            "conformance/evidence/artifacts/x/../../escape"
        )
        reject_closure("artifact traversal", [traversal], "stay inside")
        false_command = copy.deepcopy(closure_entry)
        false_command["command"] = "true"
        reject_closure("unreviewed closure command", [false_command], "reviewed stage gate")
        false_tool = copy.deepcopy(closure_entry)
        false_tool["tool"] = {"name": "sh", "version": "1"}
        reject_closure("unreviewed closure tool", [false_tool], "unreviewed gate tool")

        legacy_run_artifact = copy.deepcopy(run_artifact)
        legacy_run_artifact["schema_version"] = 1
        legacy_run_artifact.pop("toolchain_policy_sha256")
        legacy_run_artifact.pop("toolchain")
        legacy_run_artifact.pop("limitations")
        legacy_run = copy.deepcopy(closure_entry)
        legacy_run["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            legacy_run_artifact
        )
        reject_closure(
            "legacy gate-run schema",
            [legacy_run],
            "version 1 is archive-only",
        )

        stale_policy_artifact = copy.deepcopy(run_artifact)
        stale_policy_artifact["toolchain_policy_sha256"] = "0" * 64
        stale_policy = copy.deepcopy(closure_entry)
        stale_policy["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            stale_policy_artifact
        )
        reject_closure(
            "stale toolchain policy",
            [stale_policy],
            "committed toolchain policy",
        )

        missing_tool_artifact = copy.deepcopy(run_artifact)
        missing_tool_artifact["toolchain"].pop()  # type: ignore[union-attr]
        missing_tool = copy.deepcopy(closure_entry)
        missing_tool["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            missing_tool_artifact
        )
        reject_closure(
            "missing toolchain identity",
            [missing_tool],
            "reviewed stage profile",
        )

        extra_tool_artifact = copy.deepcopy(run_artifact)
        extra_tool_artifact["toolchain"].append(  # type: ignore[union-attr]
            {
                "name": "unreviewed-tool",
                "argv": ["unreviewed-tool", "--version"],
                "version": "unreviewed-tool 1.0",
            }
        )
        extra_tool = copy.deepcopy(closure_entry)
        extra_tool["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            extra_tool_artifact
        )
        reject_closure(
            "extra toolchain identity",
            [extra_tool],
            "reviewed stage profile",
        )

        wrong_tool_version_artifact = copy.deepcopy(run_artifact)
        wrong_tool_version_artifact["toolchain"][0]["version"] = "test-tool 2.0"  # type: ignore[index]
        wrong_tool_version = copy.deepcopy(closure_entry)
        wrong_tool_version["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            wrong_tool_version_artifact
        )
        reject_closure(
            "wrong toolchain version",
            [wrong_tool_version],
            "reviewed stage profile",
        )

        missing_limitations_artifact = copy.deepcopy(run_artifact)
        missing_limitations_artifact["limitations"] = []
        missing_limitations = copy.deepcopy(closure_entry)
        missing_limitations["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            missing_limitations_artifact
        )
        reject_closure(
            "missing artifact limitations",
            [missing_limitations],
            "nonempty array",
        )

        unsupported_target_artifact = copy.deepcopy(run_artifact)
        unsupported_target_artifact["target"] = "aarch64-apple-darwin"
        unsupported_target = copy.deepcopy(closure_entry)
        unsupported_target["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            unsupported_target_artifact
        )
        reject_closure(
            "unsupported evidence host",
            [unsupported_target],
            "not a reviewed conforming host",
        )

        empty_features_artifact = copy.deepcopy(run_artifact)
        empty_features_artifact["features"] = []
        empty_features = copy.deepcopy(closure_entry)
        empty_features["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            empty_features_artifact
        )
        reject_closure(
            "empty evidence features",
            [empty_features],
            "reviewed profile",
        )

        renamed_path = (
            temporary_root / "conformance/evidence/artifacts/renamed-closure.json"
        )
        renamed_hash = stage_artifact(run_artifact, renamed_path)
        renamed_artifact = copy.deepcopy(closure_entry)
        renamed_artifact["artifact"] = {
            "label": "renamed-gate-run",
            "sha256": renamed_hash,
            "path": "conformance/evidence/artifacts/renamed-closure.json",
        }
        reject_closure(
            "noncanonical artifact path",
            [renamed_artifact],
            "not canonical for the gate",
        )

        artifact_hash = stage_artifact(run_artifact)
        closure_entry["artifact"]["sha256"] = artifact_hash  # type: ignore[index]
        stale_entry_policy = copy.deepcopy(closure_entry)
        stale_entry_policy["toolchain_policy_sha256"] = "0" * 64
        reject_closure(
            "stale entry toolchain policy",
            [stale_entry_policy],
            "stale toolchain policy",
        )
        stale_entry_toolchain = copy.deepcopy(closure_entry)
        stale_entry_toolchain["toolchain"].pop()  # type: ignore[union-attr]
        reject_closure(
            "stale entry toolchain profile",
            [stale_entry_toolchain],
            "stale toolchain profile",
        )
        stale_entry_limitations = copy.deepcopy(closure_entry)
        stale_entry_limitations["limitations"] = ["Different limitation."]
        reject_closure(
            "stale entry limitations",
            [stale_entry_limitations],
            "stale limitations",
        )

        wrong_kind_artifact = copy.deepcopy(run_artifact)
        wrong_kind_artifact["evidence"][0]["kind"] = "unrelated"  # type: ignore[index]
        wrong_kind = copy.deepcopy(closure_entry)
        wrong_kind["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            wrong_kind_artifact
        )
        reject_closure("stale evidence kind", [wrong_kind], "catalog kinds are stale")

        incomplete_run_artifact = copy.deepcopy(run_artifact)
        incomplete_run_artifact["command_results"] = []
        incomplete_run = copy.deepcopy(closure_entry)
        incomplete_run["artifact"]["sha256"] = stage_artifact(  # type: ignore[index]
            incomplete_run_artifact
        )
        reject_closure("incomplete gate run", [incomplete_run], "command results are incomplete")

        unrelated_hash = stage_artifact({})
        unrelated = copy.deepcopy(closure_entry)
        unrelated["artifact"] = {
            "label": "unrelated-test",
            "sha256": unrelated_hash,
            "path": (
                "conformance/evidence/artifacts/"
                f"{gate_name}-{closure_commit}.json"
            ),
        }
        reject_closure("unrelated staged artifact", [unrelated], "schema_version must be 2")

        artifact_hash = stage_artifact(run_artifact)
        closure_entry["artifact"]["sha256"] = artifact_hash  # type: ignore[index]
        untracked_path = temporary_root / "conformance/evidence/artifacts/untracked.json"
        untracked_path.write_bytes(artifact_path.read_bytes())
        untracked = copy.deepcopy(closure_entry)
        untracked["artifact"] = {
            "label": "untracked-test",
            "sha256": hashlib.sha256(untracked_path.read_bytes()).hexdigest(),
            "path": "conformance/evidence/artifacts/untracked.json",
        }
        reject_closure("untracked artifact", [untracked], "Git index")
        artifact_path.write_bytes(b"unstaged replacement\n")
        unstaged = copy.deepcopy(closure_entry)
        unstaged["artifact"]["sha256"] = hashlib.sha256(  # type: ignore[index]
            artifact_path.read_bytes()
        ).hexdigest()
        reject_closure("unstaged artifact", [unstaged], "tracked artifact bytes")
        artifact_path.write_text(
            json.dumps(run_artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    head = git_bytes(root, ["rev-parse", "HEAD"], "current commit").decode("ascii").strip()
    source_hash = canonical_source_sha256(root, head)
    lock_hash = commit_blob_sha256(root, head, "Cargo.lock")
    bound = copy.deepcopy(valid)
    bound["source_commit"] = head
    bound["source_sha256"] = source_hash
    bound["lock_sha256"] = lock_hash
    bound_entry = bound["entries"][0]  # type: ignore[index]
    bound_entry["source_commit"] = head  # type: ignore[index]
    bound_entry["source_sha256"] = source_hash  # type: ignore[index]
    bound_entry["lock_sha256"] = lock_hash  # type: ignore[index]
    validate_manifest(
        bound,
        bindings,
        expected_source_hash=source_hash,
        expected_lock_hash=lock_hash,
    )

    stale_lock = copy.deepcopy(bound)
    replacement_lock = ("0" if lock_hash[:1] != "0" else "1") + lock_hash[1:]
    stale_lock["lock_sha256"] = replacement_lock
    stale_lock["entries"][0]["lock_sha256"] = replacement_lock  # type: ignore[index]
    try:
        validate_manifest(stale_lock, bindings, expected_lock_hash=lock_hash)
    except EvidenceError as error:
        if "does not match Cargo.lock" not in str(error):
            raise EvidenceError(f"self-test 'commit lock' reached the wrong branch: {error}") from error
    else:
        raise EvidenceError("self-test 'commit lock' was accepted")
    cases += 1

    try:
        canonical_source_sha256(root, "0" * 40)
    except EvidenceError as error:
        if "source commit" not in str(error):
            raise EvidenceError(f"self-test 'missing commit' reached the wrong branch: {error}") from error
    else:
        raise EvidenceError("self-test 'missing commit' was accepted")
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"evidence validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch archive validation, closure validation, and self-tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "close-stage", "self-test"))
    parser.add_argument("--stage", type=int)
    parser.add_argument("--source-commit")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            if arguments.stage is not None or arguments.source_commit is not None:
                raise EvidenceError("check does not accept closure arguments")
            bindings, entries = validate(root)
            print(f"evidence archive: ok ({bindings} bindings, {entries} entries)")
        elif arguments.command == "close-stage":
            if arguments.stage is None or arguments.source_commit is None:
                raise EvidenceError("close-stage requires --stage and --source-commit")
            entries, manifests = validate_closure(
                root,
                arguments.stage,
                arguments.source_commit,
            )
            print(
                f"Stage {arguments.stage:02d} evidence closure: ok "
                f"({entries} passed records in {manifests} current manifests)"
            )
        else:
            if arguments.stage is not None or arguments.source_commit is not None:
                raise EvidenceError("self-test does not accept closure arguments")
            cases = self_test(root)
            print(f"evidence schema self-test: ok ({cases} rejection cases)")
    except (EvidenceError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
