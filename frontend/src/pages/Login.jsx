import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Login() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (event) => {
    event.preventDefault();

    if (!username || !password) {
      setError("Please enter username and password.");
      return;
    }

    try {
      setLoading(true);
      setError("");

      const response = await api.post("/auth/login", {
        username,
        password,
      });

      localStorage.setItem(
        "access_token",
        response.data.access_token
      );

      if (rememberMe) {
        localStorage.setItem("remember_me", "true");
      }

      navigate("/dashboard");
    } catch (err) {
      console.error("Login error:", err);

      setError(
        err.response?.data?.detail ||
          "Invalid username or password."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">

      {/* CYBER BACKGROUND */}
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

      {/* MAIN CONTENT */}
      <div className="login-container">

        {/* BRAND */}
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

          <p>
            APPLICATION SECURITY INTELLIGENCE
          </p>

          <div className="brand-divider">
            <span></span>
          </div>

        </div>

        {/* LOGIN CARD */}
        <div className="login-card">

          <div className="login-heading">

            <h2>Welcome Back</h2>

            <p>
              Sign in to access your security dashboard
            </p>

          </div>

          <form
            className="login-form"
            onSubmit={handleLogin}
          >

            {/* USERNAME */}
            <div className="form-group">

              <label htmlFor="username">
                Username
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  👤
                </span>

                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value)
                  }
                  placeholder="Enter your username"
                  autoComplete="username"
                />

              </div>

            </div>

            {/* PASSWORD */}
            <div className="form-group">

              <label htmlFor="password">
                Password
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  🔒
                </span>

                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) =>
                    setPassword(e.target.value)
                  }
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() =>
                    setShowPassword(!showPassword)
                  }
                >
                  {showPassword ? "🙈" : "👁"}
                </button>

              </div>

            </div>

            {/* OPTIONS */}
            <div className="login-options">

              <label className="remember-me">

                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) =>
                    setRememberMe(e.target.checked)
                  }
                />

                <span className="custom-checkbox"></span>

                <span>Remember me</span>

              </label>

              <button
                type="button"
                className="forgot-password"
                onClick={() => {
                  alert("Password reset feature coming soon.");
                }}
              >
                Forgot password?
              </button>

            </div>

            {/* ERROR */}
            {error && (
              <div className="login-error">
                ⚠ {error}
              </div>
            )}

            {/* SIGN IN */}
            <button
              type="submit"
              className="login-submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="button-spinner"></span>
                  Signing in...
                </>
              ) : (
                <>
                  Sign In
                  <span className="button-arrow">→</span>
                </>
              )}
            </button>

          </form>

          {/* CREATE ACCOUNT */}
          <div className="login-footer">

            <span>
              Don't have an account?
            </span>

            <button
              type="button"
              onClick={() => navigate("/register")}
            >
              Create account
            </button>

          </div>

        </div>

        {/* SECURITY STATUS */}
        <div className="login-security">

          <span className="security-dot"></span>

          <span>
            Secure authentication
          </span>

          <span className="security-line"></span>

          <span>
            256-bit encrypted
          </span>

        </div>

      </div>

      {/* BACKGROUND SHIELD */}
      <div className="background-shield">
        ◈
      </div>

    </div>
  );
}

export default Login;