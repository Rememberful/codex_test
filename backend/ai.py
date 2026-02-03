from __future__ import annotations

import os
from typing import List

from openai import OpenAI

from .models import Finding


def generate_ai_summary(findings: List[Finding], target_url: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    model = os.getenv("OPENAI_MODEL", "gpt-5-mini")
    client = OpenAI(api_key=api_key)

    findings_text = "\n".join(
        f"- [{f.severity}] {f.category}: {f.title} ({f.description})" for f in findings
    )

    prompt = (
        "You are a security assistant helping prioritize and remediate web app vulnerabilities. "
        "Given the findings from an automated OWASP Top 10 scan, provide: "
        "(1) a short executive summary, "
        "(2) prioritized remediation steps, "
        "(3) false-positive cautions where applicable. "
        "Keep it concise and actionable.\n\n"
        f"Target: {target_url}\n\nFindings:\n{findings_text}\n"
    )

    response = client.responses.create(
        model=model,
        input=prompt,
    )

    return response.output_text
