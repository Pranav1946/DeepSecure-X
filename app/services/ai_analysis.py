import json
import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv
from openai import (
    AsyncOpenAI,
    APIConnectionError,
    APIError,
    APITimeoutError,
    RateLimitError,
)

load_dotenv()

logger = logging.getLogger("deepsecure.ai")


class AIConfigurationError(Exception):
    """Raised when AI service configuration (e.g. API key) is missing or invalid."""
    pass


class AIServiceError(Exception):
    """Raised when an error occurs while communicating with the AI service."""
    pass


class AIAnalysisService:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.timeout = float(os.getenv("OPENAI_TIMEOUT_SECONDS", "25.0"))

    def _get_client(self) -> AsyncOpenAI:
        if not self.api_key or self.api_key.strip() in ("", "your_api_key_here", "your-openai-api-key"):
            raise AIConfigurationError(
                "OpenAI API key is not configured. Please set the OPENAI_API_KEY environment variable."
            )
        return AsyncOpenAI(api_key=self.api_key.strip(), timeout=self.timeout)

    async def analyze(self, scan_result: dict[str, Any]) -> dict[str, Any]:
        client = self._get_client()

        prompt = f"""You are a senior application security engineer and security intelligence expert.
Analyze the following security scan result and provide a clear, actionable remediation report.

Return ONLY a valid JSON object matching exactly this schema:
{{
  "summary": "Concise executive security summary explaining the overall posture and primary risks",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "prioritized_remediation": [
    {{
      "priority": 1,
      "rule_id": "rule identifier (e.g. HARDCODED_SECRET, SQL_INJECTION, JS001)",
      "explanation": "Why this vulnerability is dangerous and how an attacker could exploit it",
      "remediation_steps": [
        "Step 1: Specific action to resolve",
        "Step 2: Verification step"
      ]
    }}
  ],
  "secure_practices": [
    "Secure practice recommendation 1",
    "Secure practice recommendation 2",
    "Secure practice recommendation 3"
  ]
}}

Security scan details to analyze:
{json.dumps(scan_result, indent=2)}"""

        try:
            logger.info(f"Dispatching AI analysis for scan #{scan_result.get('scan_id')} using model '{self.model}'")
            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a professional application security analyst. "
                            "You analyze vulnerabilities found in static code scans and produce structured, actionable remediation guides. "
                            "Always return valid, clean JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
            )

            choice = response.choices[0]
            content = choice.message.content
            if not content:
                raise AIServiceError("OpenAI returned an empty response.")

            analysis = json.loads(content)
            if not isinstance(analysis, dict):
                raise AIServiceError("AI response is not a valid JSON object.")

            # Ensure required schema fields exist with sensible fallbacks
            return {
                "summary": analysis.get("summary", "Analysis completed."),
                "overall_risk": analysis.get("overall_risk", "UNKNOWN"),
                "prioritized_remediation": analysis.get("prioritized_remediation", []),
                "secure_practices": analysis.get("secure_practices", []),
            }

        except AIConfigurationError:
            raise
        except APITimeoutError as exc:
            logger.error(f"OpenAI request timed out after {self.timeout}s: {exc}")
            raise AIServiceError("AI analysis request timed out. Please try again.") from exc
        except RateLimitError as exc:
            logger.error(f"OpenAI rate limit exceeded: {exc}")
            raise AIServiceError("AI service rate limit reached. Please try again shortly.") from exc
        except APIConnectionError as exc:
            logger.error(f"Failed to connect to OpenAI API: {exc}")
            raise AIServiceError("Could not connect to AI service. Please verify network connectivity.") from exc
        except APIError as exc:
            logger.error(f"OpenAI API error occurred: {exc}")
            raise AIServiceError("AI service returned an error. Please try again.") from exc
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse JSON response from OpenAI: {exc}")
            raise AIServiceError("AI service returned invalid JSON.") from exc
        except Exception as exc:
            logger.error(f"Unexpected error during AI analysis: {exc}", exc_info=True)
            raise AIServiceError(f"AI analysis failed: {str(exc)}") from exc