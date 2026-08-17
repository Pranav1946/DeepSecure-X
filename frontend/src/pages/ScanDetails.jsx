import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../services/api";

function ScanDetails() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadScan = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/scanner/history/${scanId}`
        );

        setScan(response.data);
      } catch (err) {
        console.error("Scan details error:", err);

        if (err.response?.status === 401) {
          localStorage.removeItem("access_token");
          navigate("/login");
          return;
        }

        setError(
          err.response?.data?.detail ||
            "Failed to load scan details."
        );
      } finally {
        setLoading(false);
      }
    };

    loadScan();
  }, [scanId, navigate]);

  const deleteScan = async () => {
    const confirmed = window.confirm(
      `Are you sure you want to delete Scan #${scanId}?`
    );

    if (!confirmed) return;

    try {
      await api.delete(`/scanner/history/${scanId}`);
      navigate("/dashboard");
    } catch (err) {
      console.error("Delete scan error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Failed to delete scan."
      );
    }
  };

  const getRiskClass = (risk) => {
    if (!risk) return "unknown";
    return risk.toLowerCase();
  };

  if (loading) {
    return (
      <div className="page">
        <div className="state-block">
          <div className="spinner"></div>
          Loading security report...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <div className="state-block">
          <div className="state-error-icon">!</div>
          <p>{error}</p>

          <button
            className="btn btn-secondary"
            onClick={() => navigate("/dashboard")}
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="page">
        <div className="state-block">
          Scan not found.
        </div>
      </div>
    );
  }

  const critical =
    scan.severity_counts?.CRITICAL ?? 0;

  const high =
    scan.severity_counts?.HIGH ?? 0;

  const medium =
    scan.severity_counts?.MEDIUM ?? 0;

  const low =
    scan.severity_counts?.LOW ?? 0;

  return (
    <div className="page">

      {/* =====================================
          HEADER
      ====================================== */}

      <div className="page-header scan-details-header">
        <div>
          <span className="page-eyebrow">
            SECURITY ANALYSIS
          </span>

          <h1>
            Scan #{scan.scan_id}
          </h1>

          <p>
            {scan.language}{" "}
            <span className="header-dot">•</span>{" "}
            {scan.status}
          </p>
        </div>

        <div className="page-actions">
          <button
            className="btn btn-secondary"
            onClick={() => navigate("/dashboard")}
          >
            Dashboard
          </button>

          <button
            className="btn btn-primary"
            onClick={() => navigate("/scanner")}
          >
            New Scan
          </button>

          <button
            className="btn btn-danger"
            onClick={deleteScan}
          >
            Delete
          </button>
        </div>
      </div>


      {/* =====================================
          OVERVIEW CARDS
      ====================================== */}

      <section className="scan-overview-grid">

        {/* Security Score */}

        <div className="scan-overview-card score-card">
          <div className="overview-card-top">
            <div>
              <span className="overview-label">
                SECURITY SCORE
              </span>

              <p>
                Overall protection rating
              </p>
            </div>

            <div className="overview-icon">
              ◈
            </div>
          </div>

          <div className="score-display">
            <strong>
              {scan.security_score}
            </strong>

            <span>/100</span>
          </div>

          <div className="score-bar">
            <div
              className="score-bar-fill"
              style={{
                width: `${Math.min(
                  scan.security_score || 0,
                  100
                )}%`,
              }}
            />
          </div>
        </div>


        {/* Risk */}

        <div
          className={`scan-overview-card risk-card ${getRiskClass(
            scan.risk_level
          )}`}
        >
          <div className="overview-card-top">
            <div>
              <span className="overview-label">
                CURRENT RISK
              </span>

              <p>
                Detected threat level
              </p>
            </div>

            <div className="overview-icon">
              !
            </div>
          </div>

          <div className="risk-display">
            <strong>
              {scan.risk_level}
            </strong>
          </div>

          <span className="risk-status">
            Security analysis completed
          </span>
        </div>


        {/* Vulnerabilities */}

        <div className="scan-overview-card">
          <div className="overview-card-top">
            <div>
              <span className="overview-label">
                VULNERABILITIES
              </span>

              <p>
                Issues detected
              </p>
            </div>

            <div className="overview-icon">
              ⚠
            </div>
          </div>

          <div className="big-number">
            {scan.vulnerabilities_found}
          </div>

          <span className="muted-label">
            security findings
          </span>
        </div>


        {/* Scan Status */}

        <div className="scan-overview-card">
          <div className="overview-card-top">
            <div>
              <span className="overview-label">
                SCAN STATUS
              </span>

              <p>
                Analysis result
              </p>
            </div>

            <div className="overview-icon">
              ✓
            </div>
          </div>

          <div className="status-display">
            <span
              className={`status-dot status-${(
                scan.status || ""
              ).toLowerCase()}`}
            />

            <strong>
              {scan.status}
            </strong>
          </div>

          <span className="muted-label">
            DeepSecure-X engine
          </span>
        </div>

      </section>


      {/* =====================================
          SEVERITY BREAKDOWN
      ====================================== */}

      <section className="section scan-section">

        <div className="section-header">
          <div>
            <span className="section-kicker">
              THREAT BREAKDOWN
            </span>

            <h2>
              Severity Distribution
            </h2>

            <p>
              Security findings grouped by severity level.
            </p>
          </div>
        </div>


        <div className="scan-severity-grid">

          <div className="scan-severity-card critical">
            <div className="severity-card-icon">
              !
            </div>

            <div>
              <span>CRITICAL</span>
              <strong>{critical}</strong>
              <small>issues detected</small>
            </div>
          </div>


          <div className="scan-severity-card high">
            <div className="severity-card-icon">
              ▲
            </div>

            <div>
              <span>HIGH</span>
              <strong>{high}</strong>
              <small>issues detected</small>
            </div>
          </div>


          <div className="scan-severity-card medium">
            <div className="severity-card-icon">
              ◆
            </div>

            <div>
              <span>MEDIUM</span>
              <strong>{medium}</strong>
              <small>issues detected</small>
            </div>
          </div>


          <div className="scan-severity-card low">
            <div className="severity-card-icon">
              ✓
            </div>

            <div>
              <span>LOW</span>
              <strong>{low}</strong>
              <small>issues detected</small>
            </div>
          </div>

        </div>

      </section>


      {/* =====================================
          FINDINGS
      ====================================== */}

      <section className="section scan-section">

        <div className="section-header">
          <div>
            <span className="section-kicker">
              SECURITY REPORT
            </span>

            <h2>
              Security Findings
            </h2>

            <p>
              Detailed vulnerabilities identified during this scan.
            </p>
          </div>

          <div className="finding-count">
            {scan.findings?.length ?? 0} Findings
          </div>
        </div>


        {scan.findings?.length === 0 ? (

          <div className="secure-result">
            <div className="secure-icon">
              ✓
            </div>

            <div>
              <h3>
                No vulnerabilities detected
              </h3>

              <p>
                The analyzed code passed the current
                DeepSecure-X security rules.
              </p>
            </div>
          </div>

        ) : (

          <div className="findings-list">

            {scan.findings.map(
              (finding, index) => (

                <article
                  className={`premium-finding-card ${getRiskClass(
                    finding.severity
                  )}`}
                  key={`${finding.rule_id}-${index}`}
                >

                  <div className="finding-number">
                    {(index + 1)
                      .toString()
                      .padStart(2, "0")}
                  </div>


                  <div className="premium-finding-content">

                    <div className="premium-finding-header">

                      <div>
                        <span
                          className={`severity-label ${getRiskClass(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>

                        <h3>
                          {finding.rule_id}
                        </h3>
                      </div>

                      <div className="line-badge">
                        Line {finding.line}
                      </div>

                    </div>


                    <p className="finding-description">
                      {finding.description}
                    </p>


                    <div className="finding-info-grid">

                      <div className="finding-info-box">
                        <span>
                          EVIDENCE
                        </span>

                        <code>
                          {finding.evidence}
                        </code>
                      </div>


                      <div className="finding-info-box recommendation-box">
                        <span>
                          RECOMMENDATION
                        </span>

                        <p>
                          {finding.recommendation}
                        </p>
                      </div>

                    </div>

                  </div>

                </article>

              )
            )}

          </div>

        )}

      </section>


      {/* =====================================
          SOURCE CODE
      ====================================== */}

      <section className="section scan-section">

        <div className="section-header">
          <div>
            <span className="section-kicker">
              SOURCE ANALYSIS
            </span>

            <h2>
              Analyzed Source Code
            </h2>

            <p>
              Python source code analyzed by the DeepSecure-X engine.
            </p>
          </div>

          <span className="language-badge">
            PYTHON
          </span>
        </div>


        <div className="code-window">

          <div className="code-window-header">

            <div className="code-dots">
              <span />
              <span />
              <span />
            </div>

            <span>
              scan_{scan.scan_id}.py
            </span>

            <span className="code-status">
              ANALYZED
            </span>

          </div>

          <pre className="code-preview">
            {scan.code}
          </pre>

        </div>

      </section>

    </div>
  );
}

export default ScanDetails;