import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [resetToken, setResetToken] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!email.trim()) {
      setError("Please enter your email address.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setSuccess("");
      setResetToken("");

      const response = await api.post("/auth/forgot-password", {
        email,
      });

      const message = response.data?.message || "Password reset request sent.";
      setSuccess(message);

      if (response.data?.reset_token) {
        setResetToken(response.data.reset_token);
      }
    } catch (err) {
      console.error("Forgot password error:", err);
      setError(
        err.response?.data?.detail ||
          "Unable to process the password reset request."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = () => {
    if (!resetToken) {
      return;
    }

    navigate(`/reset-password?token=${encodeURIComponent(resetToken)}`);
  };

  return (
    <div className="login-page">
      <div className="cyber-grid"></div>
      <div className="cyber-glow glow-one"></div>
      <div className="cyber-glow glow-two"></div>

      <div className="cyber-particles">
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
      </div>

      <div className="login-container">
        <div className="login-brand">
          <div className="brand-shield">
            <div className="shield-shape">
              <span className="shield-lock">🔒</span>
            </div>
          </div>

          <h1>
            <span className="brand-deep">Deep</span>
            <span className="brand-secure">Secure-X</span>
          </h1>

          <p>APPLICATION SECURITY INTELLIGENCE</p>

          <div className="brand-divider">
            <span></span>
          </div>
        </div>

        <div className="login-card">
          <div className="login-heading">
            <h2>Reset Password</h2>
            <p>Enter your email to receive a reset token</p>
          </div>

          <form className="login-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="email">Email</label>

              <div className="input-wrapper">
                <span className="input-icon">✉️</span>

                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  autoComplete="email"
                />
              </div>
            </div>

            {error && <div className="login-error">⚠ {error}</div>}
            {success && <div className="login-success">✓ {success}</div>}

            {resetToken && (
              <div className="reset-token-section">
                <div className="reset-token-title">
                  <span className="token-status-dot"></span>
                  Password Reset Token
                </div>
                <p className="reset-token-hint">
                  Your reset token is ready. Scroll inside the box to view the full token.
                </p>
                <div className="reset-token-box">
                  <code>{resetToken}</code>
                </div>
                <button
                  type="button"
                  className="login-submit reset-continue"
                  onClick={handleResetPassword}
                >
                  Continue to Reset Password
                  <span className="button-arrow">→</span>
                </button>
              </div>
            )}

            <button type="submit" className="login-submit" disabled={loading}>
              {loading ? (
                <>
                  <span className="button-spinner"></span>
                  Sending...
                </>
              ) : (
                <>
                  Send Reset Link
                  <span className="button-arrow">→</span>
                </>
              )}
            </button>
          </form>

          <div className="login-footer">
            <span>Remember your password?</span>
            <button type="button" onClick={() => navigate("/login")}>
              Back to login
            </button>
          </div>
        </div>

        <div className="login-security">
          <span className="security-dot"></span>
          <span>Secure authentication</span>
          <span className="security-line"></span>
          <span>256-bit encrypted</span>
        </div>
      </div>

      <div className="background-shield">◈</div>
    </div>
  );
}

export default ForgotPassword;
