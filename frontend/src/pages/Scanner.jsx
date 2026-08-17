import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Scanner() {
  const navigate = useNavigate();

  const [mode, setMode] = useState("paste");
  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  const scanCode = async () => {
    if (!code.trim()) {
      setError("Please enter Python code before scanning.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setResult(null);

      const response = await api.post("/scanner/python", {
        code,
      });

      setResult(response.data);
    } catch (err) {
      console.error("Scanner error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to analyze the code."
      );
    } finally {
      setLoading(false);
    }
  };

  const scanFile = async () => {
    if (!selectedFile) {
      setError("Please select a Python file before scanning.");
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".py")) {
      setError("Only Python (.py) files are supported.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setResult(null);

      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await api.post("/scanner/python/file", formData);
      setResult(response.data);
    } catch (err) {
      console.error("File scanner error:", err);

      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to analyze the Python file."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearScanner = () => {
    setCode("");
    setSelectedFile(null);
    setResult(null);
    setError("");
  };

  const getRiskClass = (risk) => {
    if (!risk) return "";

    return risk.toLowerCase();
  };

  return (
    <div className="page">

      {/* INTRO */}
      <div className="page-header">
        <div>
          <span className="page-eyebrow">Static Code Analysis</span>
          <h1>Python Security Scanner</h1>
          <p>
            Analyze Python source code for security vulnerabilities and
            receive actionable remediation recommendations.
          </p>
        </div>
      </div>

      {/* CODE EDITOR */}
      <section className="section">

        <div className="section-header">
          <div>
            <h2>Source Code</h2>
            <p>Paste code or upload a file for security analysis.</p>
          </div>
          <span className="language-badge">PYTHON</span>
        </div>

        <div className="mode-toggle">
          <button
            type="button"
            className={mode === "paste" ? "active" : ""}
            onClick={() => setMode("paste")}
          >
            Paste Code
          </button>
          <button
            type="button"
            className={mode === "upload" ? "active" : ""}
            onClick={() => setMode("upload")}
          >
            Upload File
          </button>
        </div>

        {mode === "upload" ? (
          <div className="file-upload-section">
            <div className="file-drop">
              <input
                id="python-file"
                type="file"
                accept=".py"
                onChange={(event) => {
                  setSelectedFile(event.target.files?.[0] || null);
                  setError("");
                }}
                disabled={loading}
              />
              <div className="file-drop-label">
                Drop a Python file here, or click to browse
              </div>
              <div className="file-drop-hint">Supports .py files</div>
            </div>

            {selectedFile && (
              <div>
                <span className="selected-file">{selectedFile.name}</span>
              </div>
            )}

            <div className="scanner-footer">
              <span className="code-hint">
                Security analysis is performed by DeepSecure-X
              </span>

              <div className="scanner-buttons">
                <button
                  className="btn btn-secondary"
                  onClick={clearScanner}
                  disabled={loading}
                >
                  Clear
                </button>

                <button
                  className="btn btn-primary"
                  onClick={scanFile}
                  disabled={loading || !selectedFile}
                >
                  {loading ? "Analyzing..." : "Analyze File"}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <>
            <textarea
              className="code-editor"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder={`Example:

import os

password = "SuperSecret123"

username = input("Username: ")

os.system("ping " + username)`}
              spellCheck="false"
            />

            <div className="scanner-footer">
              <span className="code-hint">
                Security analysis is performed by DeepSecure-X
              </span>

              <div className="scanner-buttons">
                <button
                  className="btn btn-secondary"
                  onClick={clearScanner}
                  disabled={loading}
                >
                  Clear
                </button>

                <button
                  className="btn btn-primary"
                  onClick={scanCode}
                  disabled={loading}
                >
                  {loading ? "Analyzing..." : "Analyze Code"}
                </button>
              </div>
            </div>
          </>
        )}

        {error && <div className="scanner-error">{error}</div>}

      </section>

      {/* RESULTS */}
      {result && (
        <section className="section results-section">

          <div className="results-header">
            <div>
              <span className="page-eyebrow">Security Analysis</span>
              <h2 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}>
                Security Report
              </h2>
              <p style={{ margin: "6px 0 0", color: "var(--text-tertiary)", fontSize: 13 }}>
                Scan #{result.scan_id} · Python
              </p>
            </div>

            <div className={`risk-badge ${getRiskClass(result.risk_level)}`}>
              {result.risk_level}
            </div>
          </div>

          <div className="result-stats">
            <div className="result-stat">
              <span>Security Score</span>
              <strong>{result.security_score}</strong>
              <small>/ 100</small>
            </div>

            <div className="result-stat">
              <span>Vulnerabilities</span>
              <strong>{result.vulnerabilities_found}</strong>
              <small>detected</small>
            </div>

            <div className="result-stat critical-stat">
              <span>Critical</span>
              <strong>{result.severity_counts?.CRITICAL ?? 0}</strong>
              <small>issues</small>
            </div>

            <div className="result-stat high-stat">
              <span>High</span>
              <strong>{result.severity_counts?.HIGH ?? 0}</strong>
              <small>issues</small>
            </div>
          </div>

          <div className="findings-heading">
            <h3>Security Findings</h3>
            <p>Vulnerabilities identified during the analysis.</p>
          </div>

          {result.findings?.length === 0 ? (
            <div className="secure-result">
              <div className="secure-icon">✓</div>
              <div>
                <h3>No vulnerabilities detected</h3>
                <p>The analyzed code passed the current security rules.</p>
              </div>
            </div>
          ) : (
            <div className="findings-list">
              {result.findings.map((finding, index) => (
                <article
                  className={`finding-card ${finding.severity?.toLowerCase()}`}
                  key={`${finding.rule_id}-${index}`}
                >
                  <div className="finding-top">
                    <div>
                      <span className="severity-label">{finding.severity}</span>
                      <h4>{finding.rule_id}</h4>
                    </div>
                    <span className="line-number">Line {finding.line}</span>
                  </div>

                  <p className="finding-description">{finding.description}</p>

                  <div className="finding-detail">
                    <strong>Evidence</strong>
                    <code>{finding.evidence}</code>
                  </div>

                  <div className="finding-detail">
                    <strong>Recommendation</strong>
                    <p>{finding.recommendation}</p>
                  </div>
                </article>
              ))}
            </div>
          )}

        </section>
      )}

    </div>
  );
}

export default Scanner;