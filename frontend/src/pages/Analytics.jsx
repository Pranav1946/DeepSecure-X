import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import "./Analytics.css";

function Analytics() {
  const navigate = useNavigate();
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadAnalytics = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get("/scanner/analytics");
        setAnalytics(response.data);
      } catch (err) {
        console.error("Analytics error:", err);

        if (err.response?.status === 401) {
          localStorage.removeItem("access_token");
          navigate("/login");
          return;
        }

        setError(
          err.response?.data?.detail ||
            "Failed to load analytics."
        );
      } finally {
        setLoading(false);
      }
    };

    loadAnalytics();
  }, [navigate]);

  if (loading) {
    return (
      <div className="analytics-page">
        <div className="state-block">
          <div className="spinner"></div>
          Loading analytics...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="analytics-page">
        <div className="state-block">
          <div className="state-error-icon">!</div>
          <p>{error}</p>
          <button className="btn btn-secondary" onClick={() => navigate("/dashboard")}>
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="analytics-page">

      <div className="analytics-header">
        <div>
          <span className="page-eyebrow">Insights</span>
          <h1>Security Analytics</h1>
          <p>Understand security trends across your scans.</p>
        </div>
      </div>

      <section className="analytics-kpi-grid">
        <div className="analytics-kpi-card">
          <div className="analytics-kpi-card-top">
            <span className="analytics-kpi-card-label">Total Scans</span>
          </div>
          <div className="analytics-kpi-card-value">{analytics?.total_scans ?? 0}</div>
        </div>

        <div className="analytics-kpi-card">
          <div className="analytics-kpi-card-top">
            <span className="analytics-kpi-card-label">Vulnerabilities</span>
          </div>
          <div className="analytics-kpi-card-value">{analytics?.total_vulnerabilities ?? 0}</div>
        </div>

        <div className="analytics-kpi-card">
          <div className="analytics-kpi-card-top">
            <span className="analytics-kpi-card-label">Average Score</span>
          </div>
          <div className="analytics-kpi-card-value">
            {analytics?.average_security_score ?? 0}
            <small>/ 100</small>
          </div>
        </div>

        <div className="analytics-kpi-card">
          <div className="analytics-kpi-card-top">
            <span className="analytics-kpi-card-label">High Risk Scans</span>
          </div>
          <div className="analytics-kpi-card-value high">
            {analytics?.risk_distribution?.HIGH ?? 0}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-header">
          <div>
            <h2>Severity Distribution</h2>
            <p>Findings across all scans, grouped by severity.</p>
          </div>
        </div>

        <div className="analytics-severity-grid">
          <div className="analytics-severity-card critical">
            <span>CRITICAL</span>
            <strong>{analytics?.severity_counts?.CRITICAL ?? 0}</strong>
          </div>
          <div className="analytics-severity-card high">
            <span>HIGH</span>
            <strong>{analytics?.severity_counts?.HIGH ?? 0}</strong>
          </div>
          <div className="analytics-severity-card medium">
            <span>MEDIUM</span>
            <strong>{analytics?.severity_counts?.MEDIUM ?? 0}</strong>
          </div>
          <div className="analytics-severity-card low">
            <span>LOW</span>
            <strong>{analytics?.severity_counts?.LOW ?? 0}</strong>
          </div>
        </div>
      </section>

      <section className="section analytics-section">
        <div className="section-header">
          <div>
            <h2>Top Vulnerabilities</h2>
            <p>Most frequently detected rule violations.</p>
          </div>
        </div>

        {!analytics?.top_vulnerabilities?.length ? (
          <div className="empty-state">No vulnerability data yet.</div>
        ) : (
          <div className="table-card">
            <div className="data-table">
              <div className="table-head cols-vulns">
                <span>Rule</span>
                <span>Count</span>
              </div>

              {analytics.top_vulnerabilities.map((item) => (
                <div className="table-row cols-vulns" key={item.rule_id}>
                  <span className="cell-primary mono">{item.rule_id}</span>
                  <span>{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="section analytics-section">
        <div className="section-header">
          <div>
            <h2>Recent Scan Activity</h2>
            <p>Latest scans across your codebase.</p>
          </div>
        </div>

        {!analytics?.scan_activity?.length ? (
          <div className="empty-state">No recent scan activity.</div>
        ) : (
          <div className="table-card">
            <div className="data-table">
              <div className="table-head cols-activity">
                <span>Scan ID</span>
                <span>Language</span>
                <span>Risk</span>
                <span>Issues</span>
              </div>

              {analytics.scan_activity.map((scan) => (
                <div className="table-row cols-activity" key={scan.scan_id}>
                  <span className="cell-id">#{scan.scan_number ?? scan.scan_id}</span>
                  <span className="cell-primary">{scan.language}</span>
                  <span>
                    <span className={`risk-badge ${(scan.risk_level || "").toLowerCase()}`}>
                      {scan.risk_level}
                    </span>
                  </span>
                  <span>{scan.vulnerabilities}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

    </div>
  );
}

export default Analytics;