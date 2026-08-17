import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import api from "../services/api";

const NAV_ITEMS = [
  {
    to: "/dashboard",
    label: "Dashboard",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <rect x="3" y="3" width="8" height="8" rx="1.5" />
        <rect x="13" y="3" width="8" height="5" rx="1.5" />
        <rect x="13" y="12" width="8" height="9" rx="1.5" />
        <rect x="3" y="13" width="8" height="8" rx="1.5" />
      </svg>
    ),
  },
  {
    to: "/scanner",
    label: "Code Scanner",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="11" cy="11" r="7" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
  },
  {
    to: "/analytics",
    label: "Analytics",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <line x1="4" y1="20" x2="4" y2="12" />
        <line x1="12" y1="20" x2="12" y2="6" />
        <line x1="20" y1="20" x2="20" y2="15" />
      </svg>
    ),
  },
];

function initialsFrom(name) {
  if (!name) return "?";
  return name.trim().slice(0, 2).toUpperCase();
}

function Layout() {
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    let active = true;

    api
      .get("/auth/me")
      .then((response) => {
        if (active) setUser(response.data);
      })
      .catch(() => {
        // Non-blocking: sidebar falls back to a generic account label.
      });

    return () => {
      active = false;
    };
  }, []);

  const logout = () => {
    localStorage.removeItem("access_token");
    navigate("/login");
  };

  const displayName =
    user?.username || user?.email || user?.name || "Account";

  const sidebarContent = (
    <>
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">DS</div>
        <div className="sidebar-brand-text">
          <strong>DeepSecure-X</strong>
          <span>App Security Intel</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="sidebar-nav-label">Workspace</span>

        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `sidebar-nav-item${isActive ? " active" : ""}`
            }
            onClick={() => setMobileOpen(false)}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-status">
          <span className="status-dot"></span>
          Security engine operational
        </div>

        <div className="sidebar-user">
          <div className="sidebar-user-avatar">
            {initialsFrom(displayName)}
          </div>
          <div className="sidebar-user-info">
            <div className="sidebar-user-name">{displayName}</div>
            <div className="sidebar-user-role">Signed in</div>
          </div>
        </div>

        <button
          type="button"
          className="btn btn-ghost btn-sm sidebar-logout-btn"
          onClick={logout}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          Logout
        </button>
      </div>
    </>
  );

  return (
    <div className="app-shell">
      <div className="mobile-topbar">
        <div className="mobile-topbar-brand">
          <div className="sidebar-brand-icon">DS</div>
          DeepSecure-X
        </div>

        <button
          type="button"
          className="mobile-menu-btn"
          onClick={() => setMobileOpen(true)}
          aria-label="Open navigation"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      </div>

      {mobileOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside className={`sidebar${mobileOpen ? " open" : ""}`}>
        {sidebarContent}
      </aside>

      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}

export default Layout;