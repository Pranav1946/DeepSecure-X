import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import "./Dashboard.css";

const SEVERITIES = [
  { key: "CRITICAL", label: "Critical", className: "critical" },
  { key: "HIGH", label: "High", className: "high" },
  { key: "MEDIUM", label: "Medium", className: "medium" },
  { key: "LOW", label: "Low", className: "low" },
];

const getRiskClass = (risk) =>
  String(risk || "UNKNOWN").toLowerCase();

function Dashboard() {
  const navigate = useNavigate();

  const [dashboard, setDashboard] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const loadDashboard = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);

      setError("");

      const [dashboardResponse, historyResponse] =
        await Promise.all([
          api.get("/scanner/dashboard"),
          api.get("/scanner/history"),
        ]);

      setDashboard(dashboardResponse.data || {});
      setHistory(historyResponse.data?.scans || []);
    } catch (err) {
      console.error("Dashboard error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to load security dashboard."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [navigate]);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const totalScans = Number(dashboard?.total_scans || 0);
  const totalVulnerabilities = Number(
    dashboard?.total_vulnerabilities || 0
  );

  const score = Number(
    dashboard?.average_security_score || 0
  );

  const risk = dashboard?.latest_risk_level || "UNKNOWN";
  const severityCounts = dashboard?.severity_counts;

  const severityTotal = useMemo(
    () =>
      SEVERITIES.reduce(
        (sum, item) =>
          sum + Number(severityCounts?.[item.key] || 0),
        0
      ),
    [severityCounts]
  );

  const trendData = useMemo(() => {
    const values = [...history]
      .reverse()
      .slice(-7)
      .map((item) =>
        Number(item.vulnerabilities_found || 0)
      );

    return values.length ? values : [0];
  }, [history]);


  const maxTrend = Math.max(...trendData, 1);

  const trendPoints = trendData
    .map((value, index) => {
      const x =
        trendData.length === 1
          ? 50
          : (index / (trendData.length - 1)) * 100;

      const y = 88 - (value / maxTrend) * 68;

      return `${x},${y}`;
    })
    .join(" ");

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    navigate("/login");
  };

  const formatTime = (index) => {
    const labels = [
      "Just now",
      "Few minutes ago",
      "32 minutes ago",
      "1 hour ago",
      "2 hours ago",
    ];

    return labels[index] || "Recently";
  };

  if (loading) {
    return (
      <div className="dash-loading">
        <div className="dash-loader"></div>
        <h3>Loading Security Intelligence</h3>
        <p>Connecting to DeepSecure-X security engine...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dash-loading">
        <div className="dash-error">!</div>
        <h3>Dashboard unavailable</h3>
        <p>{error}</p>

        <button
          className="dash-primary"
          onClick={() => loadDashboard()}
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="dashboard-shell">

      {/* SIDEBAR */}

      <aside
        className={`dashboard-sidebar ${
          sidebarOpen ? "sidebar-open" : ""
        }`}
      >
        <div className="sidebar-brand">
          <div className="brand-shield">
            <svg viewBox="0 0 48 48">
              <path
                d="M24 3L42 10V22C42 33 35 42 24 46C13 42 6 33 6 22V10L24 3Z"
              />
              <path d="M24 14L32 17V23C32 28 29 32 24 34C19 32 16 28 16 23V17L24 14Z" />
              <circle cx="24" cy="23" r="2.5" />
            </svg>
          </div>

          <div>
            <strong>DeepSecure-X</strong>
            <span>SECURITY INTELLIGENCE</span>
          </div>
        </div>

        <div className="sidebar-label">
          SECURITY CONSOLE
        </div>

        <nav className="dashboard-nav">

          <button
            className="dashboard-nav-item active"
            onClick={() => navigate("/dashboard")}
          >
            <span>▦</span>
            Dashboard
          </button>

          <button
            className="dashboard-nav-item"
            onClick={() => navigate("/scanner")}
          >
            <span>&lt;/&gt;</span>
            Code Scanner
          </button>

          <button
            className="dashboard-nav-item"
            onClick={() => navigate("/analytics")}
          >
            <span>◫</span>
            Analytics
          </button>

        </nav>

        <div className="sidebar-bottom">

          <div className="engine-status">
            <span className="status-dot"></span>

            <div>
              <strong>Security Engine</strong>
              <small>Operational</small>
            </div>
          </div>

          <div className="dashboard-user">
            <div className="user-avatar">PR</div>

            <div>
              <strong>pranav01</strong>
              <span>Security Analyst</span>
            </div>
          </div>

          <button
            className="logout-button"
            onClick={handleLogout}
          >
            ⇥
            <span>Logout</span>
          </button>

        </div>
      </aside>

      {/* MAIN */}

      <main className="dashboard-main">

        {/* HEADER */}

        <header className="dashboard-header">

          <div className="header-left">

            <button
              className="mobile-menu"
              onClick={() =>
                setSidebarOpen(!sidebarOpen)
              }
            >
              ☰
            </button>

            <div>
              <div className="header-eyebrow">
                SECURITY OPERATIONS CENTER
              </div>

              <h1>Security Dashboard</h1>

              <p>
                Monitor your application's security posture,
                vulnerabilities and scan activity.
              </p>
            </div>

          </div>

          <div className="header-actions">

            <button
              className="refresh-button"
              onClick={() => loadDashboard(true)}
              disabled={refreshing}
            >
              <span className="refresh-icon">↻</span>
              {refreshing ? "Refreshing" : "Refresh"}
            </button>

            <button
              className="dash-primary"
              onClick={() => navigate("/scanner")}
            >
              <span>＋</span>
              New Scan
            </button>

          </div>

        </header>

        {/* OVERVIEW */}

        <section className="overview-grid">

          <div className="overview-card purple">
            <div className="card-icon">⌁</div>

            <div className="card-label">
              TOTAL SCANS
            </div>

            <div className="card-value">
              {totalScans}
            </div>

            <div className="card-description">
              Security analyses performed
            </div>

            <div className="card-bottom">
              <span className="trend-positive">
                ↗ Active
              </span>
              <span>All time</span>
            </div>
          </div>

          <div className="overview-card red">
            <div className="card-icon">◆</div>

            <div className="card-label">
              VULNERABILITIES
            </div>

            <div className="card-value">
              {totalVulnerabilities}
            </div>

            <div className="card-description">
              Security issues detected
            </div>

            <div className="card-bottom">
              <span className="trend-danger">
                ● Monitoring
              </span>
              <span>All scans</span>
            </div>
          </div>

          <div className="overview-card blue">
            <div className="card-icon">◈</div>

            <div className="card-label">
              SECURITY SCORE
            </div>

            <div className="card-value">
              {score}
              <small>/100</small>
            </div>

            <div className="score-progress">
              <span
                style={{
                  width: `${Math.min(score, 100)}%`,
                }}
              />
            </div>

            <div className="card-bottom">
              <span>Protection level</span>
            </div>
          </div>

          <div className="overview-card orange">
            <div className="card-icon">◉</div>

            <div className="card-label">
              CURRENT RISK
            </div>

            <div
              className={`risk-value ${getRiskClass(risk)}`}
            >
              {risk}
            </div>

            <div className="card-description">
              Latest detected risk level
            </div>

            <div className="card-bottom">
              <span>Real-time status</span>
            </div>
          </div>

        </section>

        {/* MAIN GRID */}

        <section className="dashboard-grid">

          {/* SEVERITY */}

          <div className="dash-panel severity-panel">

            <div className="panel-header">
              <div>
                <span className="panel-kicker">
                  THREAT OVERVIEW
                </span>
                <h2>Severity Distribution</h2>
                <p>
                  Vulnerabilities grouped by severity.
                </p>
              </div>
            </div>

            <div className="severity-content">

              <div
                className="severity-donut"
                style={{
                  background:
                    severityTotal > 0
                      ? `conic-gradient(
                          #ff334d 0% ${
                            (Number(
                              severityCounts.CRITICAL || 0
                            ) /
                              severityTotal) *
                            100
                          }%,
                          #ff7a00 ${
                            (Number(
                              severityCounts.CRITICAL || 0
                            ) /
                              severityTotal) *
                            100
                          }% ${
                            ((Number(
                              severityCounts.CRITICAL || 0
                            ) +
                              Number(
                                severityCounts.HIGH || 0
                              )) /
                              severityTotal) *
                            100
                          }%,
                          #ffc400 ${
                            ((Number(
                              severityCounts.CRITICAL || 0
                            ) +
                              Number(
                                severityCounts.HIGH || 0
                              )) /
                              severityTotal) *
                            100
                          }% ${
                            ((Number(
                              severityCounts.CRITICAL || 0
                            ) +
                              Number(
                                severityCounts.HIGH || 0
                              ) +
                              Number(
                                severityCounts.MEDIUM || 0
                              )) /
                              severityTotal) *
                            100
                          }%,
                          #36d399 0
                        )`
                      : "#202b38",
                }}
              >
                <div className="donut-center">
                  <strong>
                    {severityTotal}
                  </strong>
                  <span>Findings</span>
                </div>
              </div>

              <div className="severity-list">

                {SEVERITIES.map((item) => {
                  const count = Number(
                    severityCounts[item.key] || 0
                  );

                  const percentage =
                    severityTotal > 0
                      ? Math.round(
                          (count / severityTotal) * 100
                        )
                      : 0;

                  return (
                    <div
                      className="severity-row"
                      key={item.key}
                    >
                      <div
                        className={`severity-dot ${item.className}`}
                      />

                      <span>{item.label}</span>

                      <strong>{count}</strong>

                      <small>{percentage}%</small>
                    </div>
                  );
                })}

              </div>

            </div>

          </div>

          {/* TREND */}

          <div className="dash-panel trend-panel">

            <div className="panel-header">
              <div>
                <span className="panel-kicker">
                  SECURITY ACTIVITY
                </span>
                <h2>Vulnerability Trend</h2>
                <p>
                  Findings across recent security scans.
                </p>
              </div>
            </div>

            <div className="trend-chart">

              <div className="trend-y">
                <span>{maxTrend}</span>
                <span>{Math.round(maxTrend * 0.75)}</span>
                <span>{Math.round(maxTrend * 0.5)}</span>
                <span>{Math.round(maxTrend * 0.25)}</span>
                <span>0</span>
              </div>

              <svg
                viewBox="0 0 100 100"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient
                    id="securityTrend"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#ff334d"
                      stopOpacity=".35"
                    />
                    <stop
                      offset="100%"
                      stopColor="#ff334d"
                      stopOpacity="0"
                    />
                  </linearGradient>
                </defs>

                <polygon
                  points={`0,100 ${trendPoints} 100,100`}
                  fill="url(#securityTrend)"
                />

                <polyline
                  points={trendPoints}
                  fill="none"
                  stroke="#ff334d"
                  strokeWidth="1.5"
                  vectorEffect="non-scaling-stroke"
                />

                {trendData.map((value, index) => {
                  const x =
                    trendData.length === 1
                      ? 50
                      : (index /
                          (trendData.length - 1)) *
                        100;

                  const y =
                    88 -
                    (value / maxTrend) * 68;

                  return (
                    <circle
                      key={index}
                      cx={x}
                      cy={y}
                      r="1.8"
                      fill="#ff334d"
                      stroke="#0a1018"
                      strokeWidth=".8"
                    />
                  );
                })}
              </svg>

              <div className="trend-grid">
                <span />
                <span />
                <span />
                <span />
                <span />
              </div>

            </div>

            <div className="trend-labels">
              {history.length
                ? history
                    .slice(0, 7)
                    .reverse()
                    .map((item, index) => (
                      <span key={index}>
                        #{item.scan_number || item.scan_id || index + 1}
                      </span>
                    ))
                : ["—", "—", "—", "—", "—"].map(
                    (x, i) => <span key={i}>{x}</span>
                  )}
            </div>

          </div>

          {/* ACTIVITY */}

          <div className="dash-panel activity-panel">

            <div className="panel-header compact">
              <div>
                <span className="panel-kicker">
                  LIVE FEED
                </span>
                <h2>Recent Activity</h2>
              </div>

              <button
                className="panel-action"
                onClick={() => navigate("/scanner")}
              >
                View all →
              </button>
            </div>

            <div className="activity-list">

              {!history.length ? (
                <div className="empty-mini">
                  <span>◌</span>
                  <strong>No scan activity</strong>
                  <small>
                    Run your first security scan.
                  </small>
                </div>
              ) : (
                history.slice(0, 5).map((scan, index) => {
                  const vulnerabilities = Number(
                    scan.vulnerabilities_found || 0
                  );

                  const type =
                    vulnerabilities > 10
                      ? "danger"
                      : vulnerabilities > 5
                      ? "warning"
                      : "success";

                  return (
                    <div
                      className="activity-item"
                      key={
                        scan.scan_id || index
                      }
                    >
                      <div
                        className={`activity-icon ${type}`}
                      >
                        {type === "success"
                          ? "✓"
                          : "!"}
                      </div>

                      <div className="activity-info">
                        <strong>
                          {vulnerabilities > 10
                            ? "High risk detected"
                            : "Security scan completed"}
                        </strong>

                        <span>
                          {scan.file_name ||
                            scan.filename ||
                            scan.language ||
                            `Scan #${scan.scan_id}`}
                        </span>
                      </div>

                      <time>
                        {formatTime(index)}
                      </time>
                    </div>
                  );
                })
              )}

            </div>

          </div>

        </section>

        {/* RECENT SCANS */}

        <section className="dash-panel scans-panel">

          <div className="panel-header">

            <div>
              <span className="panel-kicker">
                SCAN HISTORY
              </span>
              <h2>Recent Security Scans</h2>
              <p>
                Latest source code security analysis results.
              </p>
            </div>

            <button
              className="panel-action"
              onClick={() => navigate("/scanner")}
            >
              Open Scanner →
            </button>

          </div>

          {!history.length ? (
            <div className="empty-scans">
              <div>⌁</div>
              <h3>No security scans yet</h3>
              <p>
                Start your first scan to populate your
                security history.
              </p>

              <button
                className="dash-primary"
                onClick={() => navigate("/scanner")}
              >
                Start First Scan
              </button>
            </div>
          ) : (
            <div className="scan-table">

              <div className="scan-table-head">
                <span>SCAN</span>
                <span>FILE / PROJECT</span>
                <span>STATUS</span>
                <span>ISSUES</span>
                <span>SCORE</span>
                <span>RISK</span>
                <span></span>
              </div>

              {history.slice(0, 7).map((scan, index) => {
                const vulnerabilities = Number(
                  scan.vulnerabilities_found || 0
                );

                const scanScore = Number(
                  scan.security_score ??
                    Math.max(
                      0,
                      100 - vulnerabilities * 5
                    )
                );

                const scanRisk =
                  scan.risk_level ||
                  (vulnerabilities > 10
                    ? "HIGH"
                    : vulnerabilities > 5
                    ? "MEDIUM"
                    : "LOW");

                return (
                  <div
                    className="scan-table-row"
                    key={
                      scan.scan_id || index
                    }
                    onClick={() =>
                      navigate(
                        `/scans/${scan.scan_id}`
                      )
                    }
                  >
                    <span className="scan-id">
                      #{scan.scan_number ?? scan.scan_number ?? scan.scan_id}
                    </span>

                    <span className="scan-file">
                      {scan.file_name ||
                        scan.filename ||
                        `scan_${scan.scan_id}`}
                    </span>

                    <span>
                      <span className="scan-status">
                        <i />
                        {scan.status ||
                          "Completed"}
                      </span>
                    </span>

                    <span className="issue-count">
                      {vulnerabilities}
                    </span>

                    <span
                      className={`scan-score ${
                        scanScore < 40
                          ? "bad"
                          : scanScore < 70
                          ? "medium"
                          : "good"
                      }`}
                    >
                      {scanScore}/100
                    </span>

                    <span
                      className={`table-risk ${getRiskClass(
                        scanRisk
                      )}`}
                    >
                      {scanRisk}
                    </span>

                    <span className="row-arrow">
                      →
                    </span>
                  </div>
                );
              })}

            </div>
          )}

        </section>

        {/* FOOTER STATUS */}

        <div className="dashboard-footer">

          <div>
            <span className="footer-live"></span>
            DeepSecure-X Engine Operational
          </div>

          <span>
            Real-time security monitoring active
          </span>

        </div>

      </main>
    </div>
  );
}

export default Dashboard;