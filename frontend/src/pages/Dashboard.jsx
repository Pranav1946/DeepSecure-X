import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

const SEVERITIES = [
  {
    name: "CRITICAL",
    icon: "!",
    description: "Critical threats",
  },
  {
    name: "HIGH",
    icon: "▲",
    description: "High risk findings",
  },
  {
    name: "MEDIUM",
    icon: "◆",
    description: "Medium risk findings",
  },
  {
    name: "LOW",
    icon: "✓",
    description: "Low risk findings",
  },
];

function riskClass(risk) {
  if (!risk) return "unknown";
  return risk.toLowerCase();
}

function Dashboard() {
  const navigate = useNavigate();

  const [dashboard, setDashboard] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const [dashboardResponse, historyResponse] =
        await Promise.all([
          api.get("/scanner/dashboard"),
          api.get("/scanner/history"),
        ]);

      setDashboard(dashboardResponse.data);
      setHistory(historyResponse.data.scans || []);
    } catch (err) {
      console.error("Dashboard error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Failed to load dashboard"
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return (
      <div className="page dashboard-page">
        <div className="state-block">
          <div className="spinner"></div>
          Loading DeepSecure-X...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page dashboard-page">
        <div className="state-block">
          <div className="state-error-icon">!</div>
          <p>{error}</p>

          <button
            className="btn btn-secondary"
            onClick={loadDashboard}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page dashboard-page">

      {/* =========================================
          DASHBOARD HEADER
      ========================================= */}

      <div className="dashboard-hero">

        <div className="dashboard-hero-left">

          <div className="system-status">
            <span className="system-status-dot"></span>
            SYSTEM ONLINE
          </div>

          <span className="page-eyebrow">
            SECURITY INTELLIGENCE
          </span>

          <h1>
            Security Intelligence Dashboard
          </h1>

          <p>
            Monitor vulnerabilities, security scores and
            scan activity from one centralized security console.
          </p>

        </div>

        <div className="dashboard-actions">

          <button
            className="btn btn-secondary"
            onClick={loadDashboard}
          >
            ↻ Refresh
          </button>

          <button
            className="btn btn-primary"
            onClick={() => navigate("/scanner")}
          >
            + New Scan
          </button>

        </div>

      </div>


      {/* =========================================
          KPI CARDS
      ========================================= */}

      <section className="dashboard-kpi-grid">

        <div className="dashboard-kpi-card scans-card">

          <div className="dashboard-kpi-icon">
            ◉
          </div>

          <div className="dashboard-kpi-content">

            <span>
              TOTAL SCANS
            </span>

            <strong>
              {dashboard?.total_scans ?? 0}
            </strong>

            <small>
              Security analyses performed
            </small>

          </div>

        </div>


        <div className="dashboard-kpi-card vulnerabilities-card">

          <div className="dashboard-kpi-icon">
            ⚠
          </div>

          <div className="dashboard-kpi-content">

            <span>
              VULNERABILITIES
            </span>

            <strong>
              {dashboard?.total_vulnerabilities ?? 0}
            </strong>

            <small>
              Detected security issues
            </small>

          </div>

        </div>


        <div className="dashboard-kpi-card score-card">

          <div className="dashboard-kpi-icon">
            ◈
          </div>

          <div className="dashboard-kpi-content">

            <span>
              SECURITY SCORE
            </span>

            <strong>
              {dashboard?.average_security_score ?? 0}
              <em>/100</em>
            </strong>

            <small>
              Average protection score
            </small>

          </div>

        </div>


        <div className="dashboard-kpi-card risk-card">

          <div className="dashboard-kpi-icon">
            !
          </div>

          <div className="dashboard-kpi-content">

            <span>
              CURRENT RISK
            </span>

            <strong
              className={`risk-value ${riskClass(
                dashboard?.latest_risk_level
              )}`}
            >
              {dashboard?.latest_risk_level ?? "UNKNOWN"}
            </strong>

            <small>
              Latest detected risk level
            </small>

          </div>

        </div>

      </section>


      {/* =========================================
          THREAT ANALYSIS
      ========================================= */}

      <section className="dashboard-panel">

        <div className="dashboard-panel-header">

          <div>

            <span className="dashboard-section-label">
              THREAT ANALYSIS
            </span>

            <h2>
              Severity Distribution
            </h2>

            <p>
              Findings across all scans grouped by severity.
            </p>

          </div>

          <button
            className="btn btn-ghost btn-sm"
            onClick={loadDashboard}
          >
            ↻ Refresh
          </button>

        </div>


        <div className="dashboard-severity-grid">

          {SEVERITIES.map((severity) => {

            const value =
              dashboard?.severity_counts?.[severity.name] ?? 0;

            return (
              <div
                className={`dashboard-severity-card ${severity.name.toLowerCase()}`}
                key={severity.name}
              >

                <div className="severity-card-top">

                  <div className="severity-icon">
                    {severity.icon}
                  </div>

                  <span>
                    {severity.name}
                  </span>

                </div>

                <strong>
                  {value}
                </strong>

                <small>
                  {severity.description}
                </small>

                <div className="severity-line"></div>

              </div>
            );

          })}

        </div>

      </section>


      {/* =========================================
          RECENT SCANS
      ========================================= */}

      <section className="dashboard-panel">

        <div className="dashboard-panel-header">

          <div>

            <span className="dashboard-section-label">
              ACTIVITY MONITOR
            </span>

            <h2>
              Recent Security Scans
            </h2>

            <p>
              Recently analyzed source files and security results.
            </p>

          </div>

          <button
            className="btn btn-ghost btn-sm"
            onClick={loadDashboard}
          >
            ↻ Refresh
          </button>

        </div>


        {history.length === 0 ? (

          <div className="dashboard-empty">
            <div className="dashboard-empty-icon">
              ◌
            </div>

            <strong>
              No scans yet
            </strong>

            <p>
              Run your first security scan to see results here.
            </p>

            <button
              className="btn btn-primary"
              onClick={() => navigate("/scanner")}
            >
              Start First Scan
            </button>
          </div>

        ) : (

          <div className="dashboard-scan-list">

            <div className="dashboard-scan-header">
              <span>SCAN ID</span>
              <span>LANGUAGE</span>
              <span>STATUS</span>
              <span>ISSUES</span>
              <span></span>
            </div>


            {history.map((scan) => (

              <div
                className="dashboard-scan-row"
                key={scan.scan_id}
                onClick={() =>
                  navigate(`/scans/${scan.scan_id}`)
                }
              >

                <span className="scan-id">
                  #{scan.scan_id}
                </span>

                <span className="scan-language">
                  {scan.language}
                </span>

                <span>
                  <span
                    className={`dashboard-status status-${(
                      scan.status || ""
                    ).toLowerCase()}`}
                  >
                    <i></i>
                    {scan.status}
                  </span>
                </span>

                <span className="scan-issues">
                  {scan.vulnerabilities_found}
                </span>

                <span className="scan-arrow">
                  →
                </span>

              </div>

            ))}

          </div>

        )}

      </section>


      {/* =========================================
          SECURITY FOOTER
      ========================================= */}

      <div className="dashboard-security-footer">

        <div className="security-shield">
          ◇
        </div>

        <div>
          <strong>
            DeepSecure-X Security Engine
          </strong>

          <span>
            Real-time monitoring active
          </span>
        </div>

        <div className="live-indicator">
          <span></span>
          LIVE
        </div>

      </div>

    </div>
  );
}

export default Dashboard;