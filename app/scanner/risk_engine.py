class SecurityRiskEngine:

    SEVERITY_DEDUCTIONS = {
        "CRITICAL": 30,
        "HIGH": 18,
        "MEDIUM": 8,
        "LOW": 3,
    }

    def calculate(self, findings: list):

        score = 100

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for finding in findings:

            severity = str(
                finding.get("severity", "LOW")
            ).upper()

            if severity in severity_counts:
                severity_counts[severity] += 1

            deduction = self.SEVERITY_DEDUCTIONS.get(
                severity,
                0
            )

            score -= deduction

        # Keep score within 0-100
        score = max(0, min(100, score))

        # Risk classification
        if score >= 90:
            risk_level = "LOW"

        elif score >= 80:
            risk_level = "MEDIUM"

        elif score >= 40:
            risk_level = "HIGH"

        else:
            risk_level = "CRITICAL"

        return {
            "security_score": score,
            "risk_level": risk_level,
            "severity_counts": severity_counts,
        }