import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { BarChart3, LayoutDashboard, LogOut, Menu, ScanSearch, X } from "lucide-react";
import api from "../services/api";

const NAV_ITEMS = [
  {
    to: "/dashboard",
    label: "Dashboard",
    icon: LayoutDashboard,
  },
  {
    to: "/scanner",
    label: "Code Scanner",
    icon: ScanSearch,
  },
  {
    to: "/analytics",
    label: "Analytics",
    icon: BarChart3,
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

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("remember_me");
    sessionStorage.removeItem("access_token");
    navigate("/login", { replace: true });
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
            <item.icon aria-hidden="true" />
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
          onClick={handleLogout}
        >
          <LogOut aria-hidden="true" />
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
          {mobileOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
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