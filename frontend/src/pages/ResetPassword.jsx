import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import api from "../services/api";

function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [token, setToken] = useState(searchParams.get("token") || "");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!token.trim()) {
      setError("Reset token is required.");
      return;
    }

    if (!newPassword || newPassword.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setSuccess("");

      const response = await api.post("/auth/reset-password", {
        token,
        new_password: newPassword,
      });

      setSuccess(
        response.data?.message ||
          "Password reset successful. You can now log in."
      );

      setNewPassword("");
      setConfirmPassword("");

      setTimeout(() => {
        navigate("/login");
      }, 1500);
    } catch (err) {
      console.error("Reset password error:", err);
      setError(
        err.response?.data?.detail ||
          "Unable to reset password. Please check your reset token and try again."
      );
    } finally {
      setLoading(false);
    }
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
            <h2>Set New Password</h2>
            <p>Create a new secure password</p>
          </div>

          <form className="login-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="token">Reset Token</label>

              <div className="input-wrapper">
                <span className="input-icon">🔑</span>

                <input
                  id="token"
                  type="text"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Paste your reset token"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="newPassword">New Password</label>

              <div className="input-wrapper">
                <span className="input-icon">🔒</span>

                <input
                  id="newPassword"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  autoComplete="new-password"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>

              <div className="input-wrapper">
                <span className="input-icon">🔒</span>

                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  autoComplete="new-password"
                />
              </div>
            </div>

            {error && <div className="login-error">⚠ {error}</div>}
            {success && <div className="login-success">✓ {success}</div>}

            <button type="submit" className="login-submit" disabled={loading}>
              {loading ? (
                <>
                  <span className="button-spinner"></span>
                  Updating...
                </>
              ) : (
                <>
                  Reset Password
                  <span className="button-arrow">→</span>
                </>
              )}
            </button>
          </form>

          <div className="login-footer">
            <span>Need to log in instead?</span>
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

export default ResetPassword;
