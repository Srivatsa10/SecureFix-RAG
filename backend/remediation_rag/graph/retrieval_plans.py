"""Retrieval plans: the initial plan and the retry adjustments.

Retries change *what the generator sees*, targeted at the weakest Jev dimension:

* security_correctness -> deepen OWASP guidance and pull in input-validation helpers
* framework_fit        -> narrow internal snippets to the caller's framework / ORM kinds
* groundedness         -> widen internal recall so there is more to ground the patch in
* no scores (draft failed to parse) -> regenerate with the same retrieval
"""

from __future__ import annotations

from remediation_rag.domain import RemediationRequest, ScoreDimension
from remediation_rag.graph.state import RetrievalPlan

MAX_K = 10


def initial_plan(request: RemediationRequest, vuln_class: str, top_k: int) -> RetrievalPlan:
    internal_filters: dict[str, str | list[str]] = {"vuln_class": vuln_class}
    if request.language:
        internal_filters["language"] = [request.language.value, "any"]
    return RetrievalPlan(
        strategy="initial",
        internal_k=top_k,
        owasp_k=top_k,
        internal_filters=internal_filters,
        owasp_filters={"vuln_class": vuln_class},
    )


def adjust_plan(
    plan: RetrievalPlan, request: RemediationRequest, weakest: ScoreDimension | None
) -> RetrievalPlan:
    if weakest is None:
        return plan.model_copy(update={"strategy": "regenerate_same_context"})

    if weakest == "security_correctness":
        filters = {k: v for k, v in plan.internal_filters.items() if k not in ("kind", "framework")}
        return plan.model_copy(
            update={
                "strategy": "deepen_owasp_guidance",
                "owasp_k": min(MAX_K, plan.owasp_k + 3),
                "internal_k": min(MAX_K, plan.internal_k + 1),
                "internal_filters": filters,
                "query_focus": "allowlist validation for identifiers; bind every value",
            }
        )

    if weakest == "framework_fit":
        filters = dict(plan.internal_filters)
        if request.framework and "framework" not in filters:
            filters["framework"] = request.framework
            strategy = "narrow_to_framework"
        else:
            filters.pop("framework", None)
            filters["kind"] = ["orm", "parameterized_query"]
            strategy = "narrow_to_query_patterns"
        return plan.model_copy(
            update={
                "strategy": strategy,
                "internal_filters": filters,
                "internal_k": min(MAX_K, plan.internal_k + 2),
                "query_focus": f"{request.framework or ''} repository query conventions".strip(),
            }
        )

    # groundedness
    filters = {k: v for k, v in plan.internal_filters.items() if k not in ("kind", "framework")}
    return plan.model_copy(
        update={
            "strategy": "widen_internal_recall",
            "internal_k": min(MAX_K, plan.internal_k + 3),
            "owasp_k": min(MAX_K, plan.owasp_k + 1),
            "internal_filters": filters,
        }
    )
