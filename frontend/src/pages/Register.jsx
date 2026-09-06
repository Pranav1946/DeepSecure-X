import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleRegister = async (event) => {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (!username || !email || !password || !confirmPassword) {
      setError("Please fill in all fields.");
      return;
    }

    if (username.length < 3) {
      setError("Username must contain at least 3 characters.");
      return;
    }

    if (password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      setLoading(true);

      await api.post("/auth/register", {
        username,
        email,
        password,
      });

      setSuccess(
        "Account created successfully. Redirecting to login..."
      );

      setTimeout(() => {
        navigate("/login");
      }, 1500);
    } catch (err) {
      console.error("Registration error:", err);

      setError(
        err.response?.data?.detail ||
          "Unable to create account."
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

        {/* REGISTER CARD */}
        <div className="login-card">

          <div className="login-heading">

            <h2>Create Account</h2>

            <p>
              Create your DeepSecure-X security account
            </p>

          </div>

          <form
            className="login-form"
            onSubmit={handleRegister}
          >

            {/* USERNAME */}
            <div className="form-group">

              <label htmlFor="register-username">
                Username
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  👤
                </span>

                <input
                  id="register-username"
                  type="text"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value)
                  }
                  placeholder="Choose a username"
                  autoComplete="username"
                />

              </div>

            </div>

            {/* EMAIL */}
            <div className="form-group">

              <label htmlFor="register-email">
                Email Address
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  ✉
                </span>

                <input
                  id="register-email"
                  type="email"
                  value={email}
                  onChange={(e) =>
                    setEmail(e.target.value)
                  }
                  placeholder="Enter your email"
                  autoComplete="email"
                />

              </div>

            </div>

            {/* PASSWORD */}
            <div className="form-group">

              <label htmlFor="register-password">
                Password
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  🔒
                </span>

                <input
                  id="register-password"
                  type="password"
                  value={password}
                  onChange={(e) =>
                    setPassword(e.target.value)
                  }
                  placeholder="Create a password"
                  autoComplete="new-password"
                />

              </div>

            </div>

            {/* CONFIRM PASSWORD */}
            <div className="form-group">

              <label htmlFor="confirm-password">
                Confirm Password
              </label>

              <div className="input-wrapper">

                <span className="input-icon">
                  🔒
                </span>

                <input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) =>
                    setConfirmPassword(e.target.value)
                  }
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                />

              </div>

            </div>

            {/* ERROR */}
            {error && (
              <div className="login-error">
                ⚠ {error}
              </div>
            )}

            {/* SUCCESS */}
            {success && (
              <div className="login-success">
                ✓ {success}
              </div>
            )}

            {/* REGISTER BUTTON */}
            <button
              type="submit"
              className="login-submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="button-spinner"></span>
                  Creating account...
                </>
              ) : (
                <>
                  Create Account
                  <span className="button-arrow">
                    →
                  </span>
                </>
              )}
            </button>

          </form>

          {/* LOGIN LINK */}
          <div className="login-footer">

            <span>
              Already have an account?
            </span>

            <button
              type="button"
              onClick={() => navigate("/login")}
            >
              Sign in
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

      <div className="background-shield">
        ◈
      </div>

    </div>
  );
}

export default Register;