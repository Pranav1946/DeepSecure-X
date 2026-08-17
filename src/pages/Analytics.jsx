import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Analytics() {
  const navigate = useNavigate();

  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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

  useEffect(() => {
    loadAnalytics();
  }, []);

  if (loading) {
    return (
      <div className="dashboard-loading">
        Loading security analytics...
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard-loading">
        <p>{error}</p>

        <button onClick={loadAnalytics}>
          Retry
        </button>
      </div>
    );
  }

  const severity = analytics?.severity_distribution || {};
  const risk = analytics?.risk_distribution || {};
  const topVulnerabilities =
    analytics?.top_vulnerabilities || [];
  const recentActivity =
    analytics?.recent_activity || [];

  return (
    <div className="dashboard-page">

      {/* HEADER */}
      <header className="dashboard-header">

        <div>
          <h1>DeepSecure-X</h1>
          <p>Security Analytics</p>
        </div>

        <div className="dashboard-actions">

          <button
            className="scanner-nav-button"
            onClick={() => navigate("/dashboard")}
          >
            Dashboard
          </button>

          <button
            className="scanner-nav-button"
            onClick={() => navigate("/scanner")}
          >
            Code Scanner
          </button>

          <button
            className="logout-button"
            onClick={() => {
              localStorage.removeItem("access_token");
              navigate("/login");
            }}
          >
            Logout
          </button>

        </div>

      </header>

      <main className="dashboard-container">

        {/* TITLE */}
        <section className="dashboard-section">

          <span className="section-eyebrow">
            SECURITY INTELLIGENCE
          </span>

          <h2>Analytics Overview</h2>

          <p>
            Monitor vulnerability trends, security scores,
            risk levels and recent scanning activity.
          </p>

        </section>

        {/* SUMMARY */}
        <section className="stats-grid">

          <div className="stat-card">
            <span>Total Scans</span>
            <strong>
              {analytics?.total_scans ?? 0}
            </strong>
          </div>

          <div className="stat-card">
            <span>Total Vulnerabilities</span>
            <strong>
              {analytics?.total_vulnerabilities ?? 0}
            </strong>
          </div>

          <div className="stat-card">
            <span>Average Security Score</span>
            <strong>
              {analytics?.average_security_score ?? 0}
            </strong>
            <small>/ 100</small>
          </div>

          <div className="stat-card">
            <span>Risk Distribution</span>
            <strong>
              {Object.keys(risk).length}
            </strong>
            <small>risk levels</small>
          </div>

        </section>

        {/* SEVERITY */}
        <section className="dashboard-section">

          <h2>Severity Distribution</h2>

          <div className="severity-grid">

            <div className="severity-card critical">
              <span>CRITICAL</span>
              <strong>
                {severity.CRITICAL ?? 0}
              </strong>
            </div>

            <div className="severity-card high">
              <span>HIGH</span>
              <strong>
                {severity.HIGH ?? 0}
              </strong>
            </div>

            <div className="severity-card medium">
              <span>MEDIUM</span>
              <strong>
                {severity.MEDIUM ?? 0}
              </strong>
            </div>

            <div className="severity-card low">
              <span>LOW</span>
              <strong>
                {severity.LOW ?? 0}
              </strong>
            </div>

          </div>

        </section>

        {/* RISK */}
        <section className="dashboard-section">

          <h2>Risk Distribution</h2>

          <div className="analytics-grid">

            {Object.entries(risk).map(
              ([level, count]) => (

                <div
                  className="analytics-card"
                  key={level}
                >
                  <span>{level}</span>
                  <strong>{count}</strong>
                  <small>scans</small>
                </div>

              )
            )}

          </div>

        </section>

        {/* TOP VULNERABILITIES */}
        <section className="dashboard-section">

          <h2>Top Vulnerabilities</h2>

          {topVulnerabilities.length === 0 ? (

            <div className="empty-state">
              No vulnerability data available.
            </div>

          ) : (

            <div className="scan-table">

              <div className="table-header">
                <span>Vulnerability</span>
                <span>Severity</span>
                <span>Occurrences</span>
              </div>

              {topVulnerabilities.map(
                (item, index) => (

                  <div
                    className="table-row"
                    key={`${item.rule_id}-${index}`}
                  >

                    <span>
                      {item.rule_id}
                    </span>

                    <span className="status">
                      {item.severity}
                    </span>

                    <span>
                      {item.count}
                    </span>

                  </div>

                )
              )}

            </div>

          )}

        </section>

        {/* RECENT ACTIVITY */}
        <section className="dashboard-section">

          <div className="section-title">

            <div>
              <h2>Recent Scan Activity</h2>
              <p>
                Latest security scanning activity.
              </p>
            </div>

            <button onClick={loadAnalytics}>
              Refresh
            </button>

          </div>

          {recentActivity.length === 0 ? (

            <div className="empty-state">
              No recent scan activity.
            </div>

          ) : (

            <div className="scan-table">

              <div className="table-header">
                <span>Scan</span>
                <span>Language</span>
                <span>Vulnerabilities</span>
                <span>Risk</span>
              </div>

              {recentActivity.map(
                (scan, index) => (

                  <div
                    className="table-row"
                    key={scan.scan_id ?? index}
                  >

                    <span>
                      #{scan.scan_id}
                    </span>

                    <span>
                      {scan.language}
                    </span>

                    <span>
                      {scan.vulnerabilities_found}
                    </span>

                    <span className="status">
                      {scan.risk_level}
                    </span>

                  </div>

                )
              )}

            </div>

          )}

        </section>

      </main>

    </div>
  );
}

export default Analytics;