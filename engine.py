"""Deterministic Shadow-AI & Compliance Readiness Evaluator + Read-Only Local Footprint Scanner.

Niche 2 (`sprint-2-shadow-ai-audit`, Port 9102):
- 100% local, local-only, no-upload evaluation engine.
- Contact fields (`company_name`, `contact_name`, `contact_email`) are completely optional (zero lead-gate).
- Produces the exact Sprint 2 Diagnostic Capsule schema (`capsule_version: "1.0"`, `niche_id: 2`).
- Includes `scan_local_directory(path)` to inspect local repos, dependency manifests, env variable NAMES
  (never secret values), `.cursor`/`.claude`/MCP configs, CSV exports, and policy Markdown docs.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

SIGNAL_ROUTING_RULES = {
    k: []
    for k in (
        "unclassified_pii_or_secrets",
        "overprivileged_agent_or_db_roles",
        "vector_or_saas_exposure",
        "shadow_ai_unapproved_tools",
        "audit_logging_or_retention_gap",
        "regulatory_or_policy_drift",
        "hallucination_or_ungrounded_output",
        "missing_observability_or_hitl",
        "broken_rag_schema_or_data_hygiene",
        "manual_csv_reconciliation_bottleneck",
        "unstructured_pdf_or_doc_intake",
        "multi_cloud_config_or_telemetry_sprawl",
    )
}


NICHE_ID = 2
NICHE_SLUG = "sprint-2-shadow-ai-audit"
NICHE_TITLE = "Shadow-AI & Compliance Readiness Audit (Typically 2-3 Weeks)"

# Scoring weights (exact parity with client-assessment.html standalone JS engine; max sum = 100)
ACCOUNT_TIER_WEIGHTS: Dict[str, int] = {
    "free_consumer_accounts": 8,
    "browser_extensions_oauth": 5,
    "team_pro_unmanaged": 4,
    "api_keys_in_repos": 7,
    "enterprise_sso_zdr": 0,
}

DEPARTMENT_WEIGHTS: Dict[str, int] = {
    "legal_contracts": 3,
    "finance_ops": 3,
    "engineering": 3,
    "sales_cs": 3,
    "hr_recruiting": 2,
    "marketing_product": 2,
}

ZDR_WEIGHTS: Dict[str, int] = {
    "no": 16,
    "unknown": 13,
    "partial": 7,
    "yes_contractual": 0,
}

EGRESS_WEIGHTS: Dict[str, int] = {
    "none": 14,
    "partial_manual": 9,
    "sso_logs_only": 4,
    "full_casb_allowlist": 0,
}

POLICY_WEIGHTS: Dict[str, int] = {
    "no_ai_policy": 12,
    "outdated_it_policy_only": 10,
    "draft_not_signed": 5,
    "enforced_annual_signoff": 0,
}

COMPLIANCE_DRIVER_WEIGHTS: Dict[str, int] = {
    "hipaa_baa": 3,
    "gdpr_ccpa_eu_ai_act": 3,
    "enterprise_security_questionnaires": 2,
    "soc2_iso27001": 2,
    "pci_finra": 3,
}

CONTRACT_RESTRICTION_WEIGHTS: Dict[str, int] = {
    "strict_bans_present_unmapped": 6,
    "unknown_unscanned": 5,
    "spot_checked": 2,
    "reviewed_and_enforced": 0,
}

# Local directory scanner signatures (read-only, zero secret extraction)
SKIP_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "target",
    "vendor",
    ".tox",
    ".idea",
}

AI_SDK_CATALOG: List[Tuple[str, str, str]] = [
    ("openai", "OpenAI SDK", "LLM Provider SDK"),
    ("anthropic", "Anthropic Claude SDK", "LLM Provider SDK"),
    ("@anthropic-ai/sdk", "Anthropic Claude JS SDK", "LLM Provider SDK"),
    ("@google/genai", "Google GenAI SDK", "LLM Provider SDK"),
    ("google-genai", "Google GenAI Python SDK", "LLM Provider SDK"),
    ("google-generativeai", "Google Gemini SDK", "LLM Provider SDK"),
    ("@google-cloud/vertexai", "Google Cloud Vertex AI", "Cloud Enterprise AI"),
    ("google-cloud-aiplatform", "Google Cloud Vertex AI", "Cloud Enterprise AI"),
    ("@aws-sdk/client-bedrock-runtime", "AWS Bedrock Runtime", "Cloud Enterprise AI"),
    ("langchain", "LangChain", "Agent / Orchestration Framework"),
    ("langchain-core", "LangChain Core", "Agent / Orchestration Framework"),
    ("@langchain/core", "LangChain JS", "Agent / Orchestration Framework"),
    ("langgraph", "LangGraph", "Agent / Orchestration Framework"),
    ("llama-index", "LlamaIndex", "RAG / Orchestration Framework"),
    ("llamaindex", "LlamaIndex", "RAG / Orchestration Framework"),
    ("ollama", "Ollama Local LLM", "Local Model Runtime"),
    ("litellm", "LiteLLM Gateway/Router", "Model Router / Proxy"),
    ("crewai", "CrewAI", "Multi-Agent Framework"),
    ("pyautogen", "AutoGen", "Multi-Agent Framework"),
    ("autogen", "AutoGen", "Multi-Agent Framework"),
    ("dspy-ai", "DSPy", "Prompt / LM Framework"),
    ("dspy", "DSPy", "Prompt / LM Framework"),
    ("cohere", "Cohere SDK", "LLM Provider SDK"),
    ("mistralai", "Mistral AI SDK", "LLM Provider SDK"),
    ("@mistralai/mistralai", "Mistral AI JS SDK", "LLM Provider SDK"),
    ("groq", "Groq Cloud SDK", "LLM Provider SDK"),
    ("together", "Together AI SDK", "LLM Provider SDK"),
    ("replicate", "Replicate SDK", "Hosted Model API"),
    ("transformers", "HuggingFace Transformers", "Model Runtime"),
    ("huggingface-hub", "HuggingFace Hub", "Model Hub Client"),
    ("huggingface_hub", "HuggingFace Hub", "Model Hub Client"),
    ("pinecone", "Pinecone Vector DB", "Vector Store"),
    ("pinecone-client", "Pinecone Vector DB", "Vector Store"),
    ("@pinecone-database/pinecone", "Pinecone JS SDK", "Vector Store"),
    ("chromadb", "ChromaDB", "Vector Store"),
    ("qdrant-client", "Qdrant Vector DB", "Vector Store"),
    ("weaviate-client", "Weaviate Vector DB", "Vector Store"),
    ("ai", "Vercel AI SDK", "Frontend / Streaming AI SDK"),
    ("@ai-sdk/openai", "Vercel AI SDK (OpenAI)", "Frontend / Streaming AI SDK"),
    ("@ai-sdk/anthropic", "Vercel AI SDK (Anthropic)", "Frontend / Streaming AI SDK"),
]

AI_ENV_VAR_REGEX = re.compile(
    r"^(?:"
    r"OPENAI_[A-Z0-9_]*|"
    r"AZURE_OPENAI_[A-Z0-9_]*|"
    r"ANTHROPIC_[A-Z0-9_]*|"
    r"CLAUDE_[A-Z0-9_]*|"
    r"GEMINI_[A-Z0-9_]*|"
    r"GOOGLE_GENAI_[A-Z0-9_]*|"
    r"GOOGLE_API_KEY|"
    r"VERTEX_[A-Z0-9_]*|"
    r"BEDROCK_[A-Z0-9_]*|"
    r"AWS_BEDROCK_[A-Z0-9_]*|"
    r"COHERE_[A-Z0-9_]*|"
    r"MISTRAL_[A-Z0-9_]*|"
    r"GROQ_[A-Z0-9_]*|"
    r"TOGETHER_[A-Z0-9_]*|"
    r"REPLICATE_[A-Z0-9_]*|"
    r"LITELLM_[A-Z0-9_]*|"
    r"LANGCHAIN_[A-Z0-9_]*|"
    r"LANGSMITH_[A-Z0-9_]*|"
    r"OLLAMA_[A-Z0-9_]*|"
    r"HF_TOKEN|"
    r"HUGGINGFACE_[A-Z0-9_]*|"
    r"PINECONE_[A-Z0-9_]*|"
    r"WEAVIATE_[A-Z0-9_]*|"
    r"QDRANT_[A-Z0-9_]*|"
    r"CURSOR_[A-Z0-9_]*"
    r")$"
)


def load_demo_payload() -> Dict[str, Any]:
    demo_path = BASE_DIR / "fixtures" / "demo_payload.json"
    return json.loads(demo_path.read_text(encoding="utf-8"))


def _parse_csv_rows(csv_text: str) -> List[Dict[str, str]]:
    if not csv_text or not str(csv_text).strip():
        return []
    lines = [
        ln
        for ln in str(csv_text).splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if len(lines) < 2:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows: List[Dict[str, str]] = []
    for raw in reader:
        if not raw:
            continue
        cleaned = {
            str(k or "").strip().lower(): str(v or "").strip()
            for k, v in raw.items()
            if k is not None
        }
        if any(cleaned.values()):
            rows.append(cleaned)
    return rows


def classify_oauth_tools(csv_text: str) -> List[Dict[str, Any]]:
    rows = _parse_csv_rows(csv_text)
    classified: List[Dict[str, Any]] = []
    for r in rows:
        tool_name = r.get("tool_name", "").strip()
        if not tool_name:
            continue
        domain = r.get("domain", "").strip()
        auth_method = r.get("auth_method", "").strip()
        department = r.get("department", "").strip() or "unspecified"
        account_tier = r.get("account_tier", "").strip() or "unspecified"
        trains_on_data = r.get("trains_on_data", "").strip() or "unknown"

        tier_l = account_tier.lower()
        auth_l = auth_method.lower()
        trains_l = trains_on_data.lower()

        is_tier3 = (
            trains_l in {"yes", "true", "1", "default_opt_in"}
            or any(
                kw in tier_l or kw in auth_l
                for kw in ("free", "consumer", "personal", "extension", "unreviewed", "shadow")
            )
        )
        is_tier1 = (
            not is_tier3
            and trains_l in {"no", "false", "0", "opt_out", "zdr"}
            and any(kw in tier_l for kw in ("enterprise", "zdr", "vpc", "bedrock", "vertex", "azure"))
            and any(kw in auth_l for kw in ("sso", "saml", "oidc", "entra", "okta", "scim"))
        )

        if is_tier3:
            risk_tier = "TIER_3"
            risk_label = "Tier 3, High-Risk Consumer / Unreviewed Extension"
            rationale = "Consumer tier, unreviewed browser OAuth extension, or model training enabled."
        elif is_tier1:
            risk_tier = "TIER_1"
            risk_label = "Tier 1, Approved Enterprise ZDR"
            rationale = "SSO-governed enterprise tier with model training disabled / ZDR."
        else:
            risk_tier = "TIER_2"
            risk_label = "Tier 2, Conditional / Review Required"
            rationale = "Unmanaged team account, non-SSO OAuth, or unverified training opt-out."

        classified.append(
            {
                "tool_name": tool_name,
                "domain": domain,
                "auth_method": auth_method,
                "department": department,
                "account_tier": account_tier,
                "trains_on_data": trains_on_data,
                "risk_tier": risk_tier,
                "risk_label": risk_label,
                "rationale": rationale,
            }
        )
    return classified


def classify_vendor_models(csv_text: str) -> List[Dict[str, Any]]:
    rows = _parse_csv_rows(csv_text)
    classified: List[Dict[str, Any]] = []
    for r in rows:
        vendor_name = r.get("vendor_name", "").strip()
        if not vendor_name:
            continue
        model_or_feature = r.get("model_or_feature", "").strip() or "unspecified"
        zdr_raw = r.get("zdr_enabled", "").strip() or "unknown"
        dpa_raw = r.get("baa_or_dpa_signed", "").strip() or "unknown"
        ret_str = r.get("logging_retained_days", "0").strip()
        try:
            ret_days = int(float(ret_str))
        except ValueError:
            ret_days = 0

        zdr_l = zdr_raw.lower()
        dpa_l = dpa_raw.lower()
        zdr_ok = zdr_l in {"yes", "true", "1"}
        dpa_ok = dpa_l in {"yes", "true", "1"}

        gaps: List[str] = []
        if not zdr_ok:
            gaps.append("ZDR not enforced")
        if not dpa_ok:
            gaps.append("Missing signed DPA/BAA")
        if ret_days < 30:
            gaps.append(f"Audit log retention too short ({ret_days}d < 30d)")

        if zdr_l in {"no", "false", "0"} or (not zdr_ok and dpa_l in {"no", "false", "0"}):
            risk_tier = "TIER_3"
            risk_label = "Tier 3, High-Risk Uncovered Endpoint"
        elif zdr_ok and dpa_ok and ret_days >= 90:
            risk_tier = "TIER_1"
            risk_label = "Tier 1, Approved Enterprise ZDR"
        else:
            risk_tier = "TIER_2"
            risk_label = "Tier 2, Conditional / Controls Incomplete"

        classified.append(
            {
                "vendor_name": vendor_name,
                "model_or_feature": model_or_feature,
                "zdr_enabled": zdr_raw,
                "baa_or_dpa_signed": dpa_raw,
                "logging_retained_days": ret_days,
                "risk_tier": risk_tier,
                "risk_label": risk_label,
                "gaps": gaps,
            }
        )
    return classified


def evaluate_intake(payload: Dict[str, Any], mode: str = "production") -> Dict[str, Any]:
    """Deterministically evaluate a Sprint 2 Shadow-AI & Compliance Readiness intake."""
    prospect_in = payload.get("prospect") or {}
    inputs_in = payload.get("inputs") or {}

    # Contact fields are 100% optional (trust-first, zero lead-gate)
    company_name = str(prospect_in.get("company_name") or "").strip() or "Local Workspace (Anonymous)"
    contact_name = str(prospect_in.get("contact_name") or "").strip()
    contact_email = str(prospect_in.get("contact_email") or "").strip()
    industry = str(prospect_in.get("industry") or "general").strip() or "general"
    team_size = str(prospect_in.get("team_size") or "50-250").strip() or "50-250"

    depts = [str(x).strip() for x in (inputs_in.get("departments_using_external_ai") or []) if str(x).strip()]
    tiers = [str(x).strip() for x in (inputs_in.get("account_tiers_in_use") or []) if str(x).strip()]
    zdr_status = str(inputs_in.get("zero_data_retention_enforced") or "unknown").strip()
    egress_vis = str(inputs_in.get("egress_or_sso_visibility") or "none").strip()
    policy_status = str(inputs_in.get("policy_and_signoff_status") or "no_ai_policy").strip()
    drivers = [str(x).strip() for x in (inputs_in.get("compliance_drivers") or []) if str(x).strip()]
    contract_status = str(inputs_in.get("client_contract_ai_restrictions") or "unknown_unscanned").strip()
    oauth_csv = str(inputs_in.get("oauth_tools_csv_text") or "")
    vendor_csv = str(inputs_in.get("vendor_inventory_csv_text") or "")

    classified_tools = classify_oauth_tools(oauth_csv)
    classified_vendors = classify_vendor_models(vendor_csv)

    tier3_tools = [t for t in classified_tools if t["risk_tier"] == "TIER_3"]
    tier2_tools = [t for t in classified_tools if t["risk_tier"] == "TIER_2"]
    tier1_tools = [t for t in classified_tools if t["risk_tier"] == "TIER_1"]

    tier3_vendors = [v for v in classified_vendors if v["risk_tier"] == "TIER_3"]
    tier2_vendors = [v for v in classified_vendors if v["risk_tier"] == "TIER_2"]
    tier1_vendors = [v for v in classified_vendors if v["risk_tier"] == "TIER_1"]

    tier3_total = len(tier3_tools) + len(tier3_vendors)
    tier2_total = len(tier2_tools) + len(tier2_vendors)
    tier1_total = len(tier1_tools) + len(tier1_vendors)

    has_csv_inventory = bool(classified_tools or classified_vendors)
    flagged_tools_display = str(tier3_total) if has_csv_inventory else "Not Scanned (No CSV)"

    # Count distinct compliance & logging gaps
    compliance_gap_count = 0
    if zdr_status != "yes_contractual":
        compliance_gap_count += 1
    if egress_vis in {"none", "partial_manual"}:
        compliance_gap_count += 1
    if policy_status != "enforced_annual_signoff":
        compliance_gap_count += 1
    if contract_status in {"unknown_unscanned", "strict_bans_present_unmapped"}:
        compliance_gap_count += 1
    vendor_gap_vendors = [v for v in classified_vendors if v["gaps"]]
    if vendor_gap_vendors:
        compliance_gap_count += len(vendor_gap_vendors)

    # Exact 100-point rubric
    pts_tiers = min(20, sum(ACCOUNT_TIER_WEIGHTS.get(t, 0) for t in set(tiers)))
    pts_depts = min(12, sum(DEPARTMENT_WEIGHTS.get(d, 0) for d in set(depts)))
    pts_zdr = ZDR_WEIGHTS.get(zdr_status, 13)
    pts_egress = EGRESS_WEIGHTS.get(egress_vis, 9)
    pts_policy = POLICY_WEIGHTS.get(policy_status, 10)
    pts_drivers = min(10, sum(COMPLIANCE_DRIVER_WEIGHTS.get(c, 0) for c in set(drivers)))
    pts_contracts = CONTRACT_RESTRICTION_WEIGHTS.get(contract_status, 5)
    pts_csv = min(10, tier3_total * 2 + tier2_total * 1)

    raw_score = (
        pts_tiers
        + pts_depts
        + pts_zdr
        + pts_egress
        + pts_policy
        + pts_drivers
        + pts_contracts
        + pts_csv
    )
    headline_score = max(5, min(100, int(raw_score)))

    heavy_regs = sum(1 for d in drivers if d in {"soc2_iso27001", "hipaa_baa", "gdpr_ccpa_eu_ai_act", "pci_finra"})
    if headline_score >= 80 or (headline_score >= 65 and len(depts) >= 4 and heavy_regs >= 2):
        sprint_days = "5-7 Weeks (Phased) · Phase 1: 1-Week Triage · Phase 2: 4-6 Weeks (~160-240 hrs at 40 hrs/wk)"
    elif headline_score >= 55 or heavy_regs >= 2:
        sprint_days = "3-5 Weeks · ~120-200 hrs (at 40 hrs/wk)"
    elif headline_score >= 30:
        sprint_days = "2-3 Weeks · ~80-120 hrs (at 40 hrs/wk)"
    else:
        sprint_days = "1-2 Weeks · ~30-60 hrs (at 40 hrs/wk)"

    if headline_score >= 80:
        severity_tier = "CRITICAL"
        score_label = f"High Priority Gaps ({headline_score}/100 Checklist Score)"
    elif headline_score >= 55:
        severity_tier = "HIGH"
        score_label = f"Notable Governance Gaps ({headline_score}/100 Checklist Score)"
    elif headline_score >= 30:
        severity_tier = "MODERATE"
        score_label = f"Moderate Governance Gaps ({headline_score}/100 Checklist Score)"
    else:
        severity_tier = "LOW"
        score_label = f"Low Checklist Exposure ({headline_score}/100 Checklist Score)"

    # Build concrete, client-actionable Top Findings (zero product upsell language)
    findings: List[Dict[str, str]] = []

    if (
        "free_consumer_accounts" in tiers
        or "browser_extensions_oauth" in tiers
        or len(tier3_tools) > 0
    ):
        ext_count = sum(
            1
            for t in classified_tools
            if "extension" in t["account_tier"].lower() or "extension" in t["auth_method"].lower()
        )
        tool_examples = ", ".join(t["tool_name"] for t in tier3_tools[:4])
        detail_parts = [
            f"Employees across {max(1, len(depts))} department(s) are using consumer AI accounts or unreviewed OAuth tools."
        ]
        if tier3_tools:
            detail_parts.append(
                f"CSV audit flagged {len(tier3_tools)} Tier-3 tool(s) ({tool_examples})"
                + (f", including {ext_count} browser OAuth extension(s)." if ext_count else ".")
            )
        findings.append(
            {
                "id": "SA-01",
                "severity": "CRITICAL" if (len(tier3_tools) >= 3 or "free_consumer_accounts" in tiers) else "HIGH",
                "title": "Personal AI Accounts or Unchecked Browser Extensions in Use",
                "detail": " ".join(detail_parts),
                "client_next_step": "Review connected Google/Microsoft apps, remove unapproved browser extensions, and move teams onto an IT-managed business AI account.",
            }
        )

    if zdr_status != "yes_contractual" or len(tier3_vendors) > 0:
        uncovered_names = ", ".join(v["vendor_name"] for v in (tier3_vendors + tier2_vendors)[:3])
        findings.append(
            {
                "id": "SA-02",
                "severity": "CRITICAL" if zdr_status == "no" else "HIGH",
                "title": "AI Providers May Retain or Train on Company Data",
                "detail": (
                    f"Data-retention protection is marked '{zdr_status}'"
                    + (
                        f", and your vendor list includes tools without full privacy agreements ({uncovered_names}). "
                        if uncovered_names
                        else ". "
                    )
                    + "Prompts containing customer info, contracts, or code may be stored by providers or used for model training."
                ),
                "client_next_step": "Sign business privacy agreements (with model training turned off) and replace personal or self-serve API keys that lack privacy terms.",
            }
        )

    if egress_vis in {"none", "partial_manual"} or len(vendor_gap_vendors) > 0:
        findings.append(
            {
                "id": "SA-03",
                "severity": "HIGH" if egress_vis == "none" else "MODERATE",
                "title": "Limited Visibility into Which AI Websites & Apps Staff Use",
                "detail": (
                    f"Visibility is marked '{egress_vis}', making it hard to see which external AI tools receive company data or answer audit questions."
                ),
                "client_next_step": "Keep a clear approved-AI list and enable central login or network logs so IT can review connected AI apps.",
            }
        )

    if policy_status != "enforced_annual_signoff" or drivers:
        driver_list = ", ".join(drivers) if drivers else "upcoming customer security reviews"
        findings.append(
            {
                "id": "SA-04",
                "severity": "HIGH" if policy_status in {"no_ai_policy", "outdated_it_policy_only"} else "MODERATE",
                "title": "AI Usage Policy & Customer Security Questionnaire Gap",
                "detail": (
                    f"Policy status is '{policy_status}' while preparing for ({driver_list}). "
                    "Enterprise buyers and auditors increasingly ask for a signed staff AI policy and human-review rules."
                ),
                "client_next_step": "Publish a short, clear AI Usage Policy (what staff can and cannot paste into AI) with employee sign-off and standard security-questionnaire answers.",
            }
        )

    if "api_keys_in_repos" in tiers or contract_status in {"unknown_unscanned", "strict_bans_present_unmapped"}:
        findings.append(
            {
                "id": "SA-05",
                "severity": "HIGH" if "api_keys_in_repos" in tiers else "MODERATE",
                "title": "Shared AI Keys in Code Projects or Unchecked Client Contract Limits",
                "detail": (
                    f"Client contract AI review status is '{contract_status}'"
                    + (
                        " and direct AI API keys live inside code folders or `.env` files without central tracking."
                        if "api_keys_in_repos" in tiers
                        else "."
                    )
                ),
                "client_next_step": "Move shared `.env` API keys into a managed secret store and check customer contracts for clauses that restrict external AI tools.",
            }
        )

    if not findings:
        findings.append(
            {
                "id": "SA-00",
                "severity": "LOW",
                "title": "Core AI Governance Safeguards Are in Place",
                "detail": "Managed logins, no-training privacy terms, staff policy sign-offs, and app visibility are active.",
                "client_next_step": "Review connected Google/Microsoft apps quarterly and keep your security-questionnaire answers up to date.",
            }
        )

    # Build practical standalone Safe-to-Deploy Checklist
    checklist: List[Dict[str, Any]] = [
        {
            "step": 1,
            "category": "Connected Apps",
            "item": "Export connected Google Workspace / Microsoft apps and browser extensions; remove unapproved personal AI add-ons.",
            "status": "ACTION_REQUIRED" if ("browser_extensions_oauth" in tiers or "free_consumer_accounts" in tiers or tier3_tools) else "VERIFIED",
        },
        {
            "step": 2,
            "category": "Privacy & No-Training Terms",
            "item": "Confirm signed business privacy agreements (with model training disabled) on every AI tool used for work.",
            "status": "ACTION_REQUIRED" if (zdr_status != "yes_contractual" or tier3_vendors or tier2_vendors) else "VERIFIED",
        },
        {
            "step": 3,
            "category": "App & Usage Logs",
            "item": "Maintain an approved AI tools list and keep central logs for audits and customer reviews.",
            "status": "ACTION_REQUIRED" if (egress_vis != "full_casb_allowlist" or vendor_gap_vendors) else "VERIFIED",
        },
        {
            "step": 4,
            "category": "API Keys in Code",
            "item": "Check code folders and `.env` files for shared OpenAI/Anthropic/Gemini keys and move them to managed secrets.",
            "status": "ACTION_REQUIRED" if "api_keys_in_repos" in tiers else "REVIEW_RECOMMENDED",
        },
        {
            "step": 5,
            "category": "Staff AI Policy",
            "item": "Share a clear 1-page AI Usage Policy (listing what private data must never be pasted into AI) with staff sign-off.",
            "status": "ACTION_REQUIRED" if policy_status != "enforced_annual_signoff" else "VERIFIED",
        },
        {
            "step": 6,
            "category": "Client Contracts & Audits",
            "item": "Check customer contracts for AI restrictions and keep ready-to-send answers for buyer security questionnaires.",
            "status": "ACTION_REQUIRED" if (contract_status != "reviewed_and_enforced" or "enterprise_security_questionnaires" in drivers) else "VERIFIED",
        },
    ]

    # Emit only registered diagnostic signal keys
    routing_signals: List[str] = []
    if (
        "free_consumer_accounts" in tiers
        or "browser_extensions_oauth" in tiers
        or "team_pro_unmanaged" in tiers
        or egress_vis != "full_casb_allowlist"
        or len(tier3_tools) > 0
        or len(tier2_tools) > 0
    ):
        routing_signals.append("shadow_ai_unapproved_tools")

    if (
        policy_status != "enforced_annual_signoff"
        or len(drivers) > 0
        or contract_status in {"unknown_unscanned", "strict_bans_present_unmapped", "spot_checked"}
    ):
        routing_signals.append("regulatory_or_policy_drift")

    if (
        zdr_status != "yes_contractual"
        or egress_vis in {"none", "partial_manual"}
        or len(vendor_gap_vendors) > 0
    ):
        routing_signals.append("audit_logging_or_retention_gap")

    if (
        "api_keys_in_repos" in tiers
        or (
            any(d in depts for d in ("finance_ops", "hr_recruiting", "sales_cs", "legal_contracts"))
            and zdr_status in {"no", "unknown"}
        )
        or (any(c in drivers for c in ("hipaa_baa", "pci_finra")) and zdr_status != "yes_contractual")
    ):
        routing_signals.append("unclassified_pii_or_secrets")

    if (
        any(d in depts for d in ("legal_contracts", "finance_ops"))
        or contract_status in {"unknown_unscanned", "strict_bans_present_unmapped"}
    ):
        routing_signals.append("unstructured_pdf_or_doc_intake")

    if egress_vis in {"sso_logs_only", "partial_manual"} and (len(classified_tools) + len(classified_vendors)) >= 4:
        routing_signals.append("multi_cloud_config_or_telemetry_sprawl")

    capsule: Dict[str, Any] = {
        "capsule_version": "1.0",
        "niche_id": NICHE_ID,
        "niche_slug": NICHE_SLUG,
        "niche_title": NICHE_TITLE,
        "mode": mode if mode in {"production", "demo"} else "production",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "prospect": {
            "company_name": company_name,
            "contact_name": contact_name,
            "contact_email": contact_email,
            "industry": industry,
            "team_size": team_size,
        },
        "inputs": {
            "departments_using_external_ai": depts,
            "account_tiers_in_use": tiers,
            "zero_data_retention_enforced": zdr_status,
            "egress_or_sso_visibility": egress_vis,
            "policy_and_signoff_status": policy_status,
            "compliance_drivers": drivers,
            "client_contract_ai_restrictions": contract_status,
            "oauth_tools_csv_text": oauth_csv,
            "vendor_inventory_csv_text": vendor_csv,
        },
        "client_assessment": {
            "headline_score": headline_score,
            "score_label": score_label,
            "severity_tier": severity_tier,
            "estimated_sprint_days": sprint_days,
            "key_metrics": [
                {"label": "Checklist Score", "value": f"{headline_score} / 100"},
                {"label": "High-Risk Tools (from CSV)", "value": flagged_tools_display},
                {"label": "Policy & Visibility Gaps", "value": str(compliance_gap_count)},
                {"label": "Estimated Effort", "value": sprint_days},
            ],
            "vendor_tier_breakdown": {
                "tier_1_approved_count": tier1_total,
                "tier_2_conditional_count": tier2_total,
                "tier_3_high_risk_count": tier3_total,
                "classified_oauth_tools": classified_tools,
                "classified_vendors": classified_vendors,
            },
            "top_findings": findings,
            "safe_to_deploy_checklist": checklist,
        },
        "routing_signals": routing_signals,
    }

    if payload.get("local_scan_metadata"):
        capsule["local_scan_metadata"] = payload["local_scan_metadata"]

    return capsule


def _extract_env_var_names_only(text: str) -> List[str]:
    """Extract ONLY variable names (never values!) matching AI/LLM patterns."""
    found: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        # Handle KEY=VALUE or YAML `KEY: value` / `- KEY=value`
        line = line.lstrip("- ").strip()
        sep = "=" if "=" in line else (":" if ":" in line else None)
        if not sep:
            continue
        key = line.split(sep, 1)[0].strip().strip("'\"")
        if AI_ENV_VAR_REGEX.match(key) and key not in found:
            found.append(key)
    return found


def _scan_manifest_for_sdks(filename: str, content: str) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    seen: Set[str] = set()
    lower_name = filename.lower()

    if lower_name == "package.json":
        try:
            pkg = json.loads(content)
            deps: Dict[str, Any] = {}
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                if isinstance(pkg.get(section), dict):
                    deps.update(pkg[section])
            dep_keys_lower = {str(k).lower(): str(k) for k in deps.keys()}
            for sig, label, category in AI_SDK_CATALOG:
                if sig.lower() in dep_keys_lower and sig not in seen:
                    seen.add(sig)
                    hits.append({"package": dep_keys_lower[sig.lower()], "label": label, "category": category})
        except Exception:
            pass
    else:
        # Line/token match for requirements.txt, pyproject.toml, Pipfile, go.mod, Cargo.toml
        tokens = set(re.findall(r"[@a-zA-Z0-9_\-/]+", content.lower()))
        for sig, label, category in AI_SDK_CATALOG:
            if sig == "ai":
                continue  # `ai` shorthand only valid in npm package.json
            if sig.lower() in tokens and sig not in seen:
                seen.add(sig)
                hits.append({"package": sig, "label": label, "category": category})
    return hits


def scan_local_directory(target_path: str, max_files: int = 2500) -> Dict[str, Any]:
    """Read-only local footprint scanner for repos, AI SDKs, env var NAMES, MCP/agent configs & policy docs.

    STRICT PRIVACY GUARANTEE:
    - Never reads or returns secret values from `.env` or MCP config `env` blocks.
    - Never makes any network calls.
    """
    raw_path = Path(str(target_path or "").strip()).expanduser()
    if not raw_path.exists():
        raise FileNotFoundError(f"Directory does not exist: {raw_path}")
    if not raw_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {raw_path}")

    root = raw_path.resolve()
    files_inspected = 0
    truncated = False

    ai_sdks: List[Dict[str, Any]] = []
    ai_env_vars: List[Dict[str, Any]] = []
    agent_and_mcp_configs: List[Dict[str, Any]] = []
    policy_docs: List[Dict[str, Any]] = []
    discovered_csvs: List[Dict[str, Any]] = []
    folder_Rollup: Dict[str, Dict[str, int]] = {}

    def _bump_folder(rel_file: str, kind: str) -> None:
        top = rel_file.split("/")[0] if "/" in rel_file else "(root)"
        bucket = folder_Rollup.setdefault(
            top,
            {"sdks": 0, "env_vars": 0, "agent_configs": 0, "policy_docs": 0, "csv_exports": 0},
        )
        bucket[kind] = bucket.get(kind, 0) + 1

    for current_root, dirs, files in os.walk(root):
        # Prune ignored directories in-place
        dirs[:] = sorted([d for d in dirs if d not in SKIP_DIRS])
        rel_dir = Path(current_root).resolve().relative_to(root).as_posix()

        # Check for `.cursor` or `.claude` or `.continue` directories themselves
        for special_dir, label in (
            (".cursor", "Cursor Workspace Config Directory"),
            (".claude", "Claude Code Workspace Directory"),
            (".continue", "Continue AI Assistant Directory"),
        ):
            if special_dir in dirs:
                rel_special = f"{rel_dir}/{special_dir}".lstrip("./")
                agent_and_mcp_configs.append(
                    {
                        "path": rel_special,
                        "type": label,
                        "mcp_servers": [],
                    }
                )
                _bump_folder(rel_special, "agent_configs")

        for fname in sorted(files):
            if files_inspected >= max_files:
                truncated = True
                break
            fpath = Path(current_root) / fname
            rel_path = fpath.resolve().relative_to(root).as_posix()
            fname_l = fname.lower()
            files_inspected += 1

            # 1. Agent rules & MCP configuration files
            if fname_l in {
                ".cursorrules",
                ".windsurfrules",
                "claude.md",
                "agents.md",
                "copilot-instructions.md",
                "mcp.json",
                ".mcp.json",
                "claude_desktop_config.json",
                "cursor_mcp.json",
                "mcp_config.json",
            }:
                mcp_servers: List[str] = []
                if fname_l.endswith(".json"):
                    try:
                        cfg = json.loads(fpath.read_text(encoding="utf-8", errors="ignore")[:200_000])
                        if isinstance(cfg, dict):
                            srv_map = cfg.get("mcpServers") or cfg.get("servers") or {}
                            if isinstance(srv_map, dict):
                                mcp_servers = [str(k) for k in srv_map.keys()]
                    except Exception:
                        pass
                agent_and_mcp_configs.append(
                    {
                        "path": rel_path,
                        "type": "MCP Server Config" if fname_l.endswith(".json") else "AI Agent Instructions / Rules",
                        "mcp_servers": mcp_servers,
                    }
                )
                _bump_folder(rel_path, "agent_configs")

            # 2. Dependency manifests -> AI SDK detection
            if (
                fname_l in {"package.json", "pyproject.toml", "pipfile", "go.mod", "cargo.toml"}
                or (fname_l.startswith("requirements") and fname_l.endswith(".txt"))
            ):
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")[:300_000]
                    sdk_hits = _scan_manifest_for_sdks(fname, content)
                    for hit in sdk_hits:
                        ai_sdks.append(
                            {
                                "manifest": rel_path,
                                "package": hit["package"],
                                "label": hit["label"],
                                "category": hit["category"],
                            }
                        )
                        _bump_folder(rel_path, "sdks")
                except Exception:
                    pass

            # 3. Environment files -> variable NAMES only (never secret values)
            if (
                fname_l == ".env"
                or fname_l.startswith(".env.")
                or fname_l in {"docker-compose.yml", "docker-compose.yaml"}
            ):
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")[:200_000]
                    var_names = _extract_env_var_names_only(content)
                    is_live_env = fname_l in {".env", ".env.local", ".env.production", ".env.development"}
                    for vname in var_names:
                        ai_env_vars.append(
                            {
                                "file": rel_path,
                                "var_name": vname,
                                "value_redacted": True,
                                "source_risk": "live_env_file" if is_live_env else "template_or_compose",
                            }
                        )
                        _bump_folder(rel_path, "env_vars")
                except Exception:
                    pass

            # 4. CSV exports (OAuth / AI tool / Vendor inventories)
            if fname_l.endswith(".csv"):
                try:
                    sample_text = fpath.read_text(encoding="utf-8", errors="ignore")[:250_000]
                    first_non_empty = next(
                        (ln.strip() for ln in sample_text.splitlines() if ln.strip() and not ln.strip().startswith("#")),
                        "",
                    )
                    headers = [h.strip().lower() for h in first_non_empty.split(",") if h.strip()]
                    csv_kind: Optional[str] = None
                    if {"tool_name", "account_tier"} & set(headers) or "trains_on_data" in headers:
                        csv_kind = "oauth_tools_csv"
                    elif {"vendor_name", "zdr_enabled"} & set(headers) or "baa_or_dpa_signed" in headers:
                        csv_kind = "vendor_inventory_csv"
                    elif any(k in fname_l for k in ("oauth", "shadow", "vendor", "ai_tools", "models")):
                        csv_kind = "candidate_inventory_csv"

                    if csv_kind:
                        parsed_rows = _parse_csv_rows(sample_text)
                        discovered_csvs.append(
                            {
                                "path": rel_path,
                                "csv_kind": csv_kind,
                                "row_count": len(parsed_rows),
                                "headers": headers[:10],
                                # Only load text if non-empty data rows exist so blank templates aren't noisy
                                "csv_preview_text": sample_text if len(parsed_rows) > 0 else "",
                            }
                        )
                        _bump_folder(rel_path, "csv_exports")
                except Exception:
                    pass

            # 5. Governance / Policy / Security Markdown documents
            if fname_l.endswith(".md") and any(
                kw in fname_l
                for kw in (
                    "policy",
                    "governance",
                    "security",
                    "privacy",
                    "acceptable",
                    "compliance",
                    "handbook",
                    "ai",
                    "outreach",
                    "charter",
                )
            ):
                try:
                    md_text = fpath.read_text(encoding="utf-8", errors="ignore")[:200_000]
                    md_l = md_text.lower()
                    mentions_ai_policy = any(
                        p in md_l for p in ("acceptable use", "acceptable-use", "ai policy", "shadow ai", "shadow-ai")
                    )
                    mentions_zdr = any(
                        p in md_l for p in ("zero data retention", "zdr", "trains_on_data", "training opt-out")
                    )
                    mentions_frameworks = [
                        fw
                        for fw, pat in (
                            ("SOC 2", "soc 2"),
                            ("ISO 27001", "iso 27001"),
                            ("HIPAA", "hipaa"),
                            ("EU AI Act", "eu ai act"),
                            ("GDPR", "gdpr"),
                        )
                        if pat in md_l
                    ]
                    first_heading = next(
                        (ln.lstrip("# ").strip() for ln in md_text.splitlines() if ln.strip().startswith("#")),
                        fname,
                    )
                    policy_docs.append(
                        {
                            "path": rel_path,
                            "title": first_heading[:90],
                            "mentions_ai_policy": mentions_ai_policy,
                            "mentions_zdr": mentions_zdr,
                            "frameworks_referenced": mentions_frameworks,
                        }
                    )
                    _bump_folder(rel_path, "policy_docs")
                except Exception:
                    pass

        if truncated:
            break

    # Synthesize optional vendor inventory rows from discovered SDKs so user can 1-click populate the assessment
    unique_sdk_labels = sorted({item["label"] for item in ai_sdks})
    synth_vendor_lines = ["vendor_name,model_or_feature,zdr_enabled,baa_or_dpa_signed,logging_retained_days"]
    for item in ai_sdks:
        lbl = item["label"]
        pkg = item["package"]
        is_cloud_ent = item["category"] == "Cloud Enterprise AI"
        is_local = item["category"] == "Local Model Runtime"
        zdr_guess = "yes" if (is_cloud_ent or is_local) else "unknown"
        dpa_guess = "unknown" if not is_local else "yes"
        synth_vendor_lines.append(f"{lbl},{pkg},{zdr_guess},{dpa_guess},0")
    # Deduplicate synthesized lines preserving order
    dedup_synth_lines = list(dict.fromkeys(synth_vendor_lines))

    has_live_env_keys = any(v["source_risk"] == "live_env_file" for v in ai_env_vars)
    suggested_tiers: List[str] = []
    if ai_env_vars or ai_sdks:
        if has_live_env_keys or ai_env_vars:
            suggested_tiers.append("api_keys_in_repos")

    return {
        "scanned_root": str(root),
        "scanned_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "files_inspected": files_inspected,
        "truncated": truncated,
        "privacy_guarantee": "Read-only local scan. No automatic external uploads. Secret/token values after '=' are discarded in memory and never stored or returned.",
        "counts": {
            "ai_sdks_found": len(ai_sdks),
            "unique_ai_sdks": len(unique_sdk_labels),
            "ai_env_vars_found": len(ai_env_vars),
            "live_env_vars_found": sum(1 for v in ai_env_vars if v["source_risk"] == "live_env_file"),
            "agent_and_mcp_configs_found": len(agent_and_mcp_configs),
            "policy_docs_found": len(policy_docs),
            "csv_exports_found": len(discovered_csvs),
        },
        "directory_breakdown": [
            {"folder": k, **v} for k, v in sorted(folder_Rollup.items(), key=lambda kv: kv[0])
        ],
        "ai_sdks": ai_sdks,
        "ai_env_vars": ai_env_vars,
        "agent_and_mcp_configs": agent_and_mcp_configs,
        "policy_docs": policy_docs,
        "discovered_csvs": discovered_csvs,
        "suggested_assessment_merge": {
            "recommended_departments": ["engineering"] if (ai_sdks or ai_env_vars or agent_and_mcp_configs) else [],
            "recommended_account_tiers": suggested_tiers,
            "synthesized_vendor_csv": "\n".join(dedup_synth_lines) if len(dedup_synth_lines) > 1 else "",
        },
    }


def render_markdown_report(capsule: Dict[str, Any]) -> str:
    """Render a printable Markdown summary.

    """
    prospect = capsule.get("prospect") or {}
    ca = capsule.get("client_assessment") or {}
    breakdown = ca.get("vendor_tier_breakdown") or {}

    lines: List[str] = [
        f"# {capsule.get('niche_title', NICHE_TITLE)}",
        f"**Governance Readiness Snapshot** | Generated: `{capsule.get('generated_at', '')}` | Mode: `{capsule.get('mode', 'production')}`",
        "",
        "## Organization Context",
        f"- **Workspace / Organization:** {prospect.get('company_name') or 'Local Workspace (Anonymous)'}",
        f"- **Industry:** `{prospect.get('industry', 'general')}` | **Team Size:** `{prospect.get('team_size', '50-250')}`",
    ]
    if prospect.get("contact_name") or prospect.get("contact_email"):
        lines.append(
            f"- **Contact (Optional):** {prospect.get('contact_name', '')} {('<' + prospect['contact_email'] + '>') if prospect.get('contact_email') else ''}".strip()
        )

    lines.extend(
        [
            "",
            "## Executive Readiness Summary",
            f"- **Headline Score:** **{ca.get('score_label', '')}**",
            f"- **Severity Tier:** `{ca.get('severity_tier', '')}`",
            f"- **Estimated Audit Turnaround:** `{ca.get('estimated_sprint_days', 'Typically 2-3 Weeks')}`",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
        ]
    )
    for m in ca.get("key_metrics") or []:
        lines.append(f"| {m.get('label', '')} | **{m.get('value', '')}** |")

    classified_tools = breakdown.get("classified_oauth_tools") or []
    classified_vendors = breakdown.get("classified_vendors") or []
    if classified_tools or classified_vendors:
        lines.extend(
            [
                "",
                "## 3-Tier Shadow-AI & Vendor Classification",
                f"- **Tier 1 (Approved Enterprise ZDR):** `{breakdown.get('tier_1_approved_count', 0)}`",
                f"- **Tier 2 (Conditional / Controls Incomplete):** `{breakdown.get('tier_2_conditional_count', 0)}`",
                f"- **Tier 3 (High-Risk Consumer / Uncovered):** `{breakdown.get('tier_3_high_risk_count', 0)}`",
            ]
        )
        if classified_tools:
            lines.extend(
                [
                    "",
                    "### Discovered OAuth Apps & AI Tools",
                    "| Tool | Auth Method | Dept | Account Tier | Trains on Data | Risk Tier |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for t in classified_tools:
                lines.append(
                    f"| {t['tool_name']} | `{t['auth_method']}` | `{t['department']}` | `{t['account_tier']}` | `{t['trains_on_data']}` | **{t['risk_label']}** |"
                )
        if classified_vendors:
            lines.extend(
                [
                    "",
                    "### AI Vendor & Model Endpoints",
                    "| Vendor | Model / Feature | ZDR | DPA / BAA | Retention (Days) | Risk Tier |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for v in classified_vendors:
                lines.append(
                    f"| {v['vendor_name']} | `{v['model_or_feature']}` | `{v['zdr_enabled']}` | `{v['baa_or_dpa_signed']}` | `{v['logging_retained_days']}` | **{v['risk_label']}** |"
                )

    lines.extend(["", "## Top Governance & Shadow-AI Findings"])
    for f in ca.get("top_findings") or []:
        lines.extend(
            [
                f"### [{f.get('id')}] ({f.get('severity')}) {f.get('title')}",
                f"- **Observation:** {f.get('detail')}",
                f"- **Recommended Action:** {f.get('client_next_step')}",
                "",
            ]
        )

    lines.extend(
        [
            "## Safe-to-Deploy Governance Checklist",
            "| Step | Category | Control Item | Status |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for item in ca.get("safe_to_deploy_checklist") or []:
        lines.append(
            f"| {item.get('step')} | {item.get('category')} | {item.get('item')} | `{item.get('status')}` |"
        )

    lines.extend(
        [
            "",
            "---",
            "> **Handling this internally?** Use the checklist above freely. **Want a focused readiness audit (typically 2-3 weeks) & buyer-ready governance pack?** Export a sanitized metadata capsule (`varinull-capsule-sprint2.json`) whenever you want VARINULL's help.",
        ]
    )

    return "\n".join(lines).strip() + "\n"
