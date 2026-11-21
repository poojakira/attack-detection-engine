import { useState } from "react";
import { BrowserRouter, Link, Navigate, Route, Routes } from "react-router-dom";
import { getSession, login, logout } from "./api/client";
import { Workbench } from "./screens/Workbench";
import { Overview } from "./screens/Overview";
import { IncidentQueue } from "./screens/IncidentQueue";
import { Investigation } from "./screens/Investigation";

function LoginForm({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login(username, password);
      onLogin();
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <div className="login">
      <h1>Aegis HealthSec</h1>
      <p className="muted">Security Operations Console</p>
      <form onSubmit={submit}>
        <input aria-label="Username" autoComplete="username" placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input aria-label="Password" autoComplete="current-password" placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Sign in</button>
      </form>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

export function App() {
  const [authed, setAuthed] = useState<boolean>(!!getSession().token);
  const session = getSession();

  if (!authed) return <LoginForm onLogin={() => setAuthed(true)} />;

  return (
    <BrowserRouter>
      <div className="shell">
        <nav className="sidebar">
          <div className="brand">Aegis HealthSec</div>
          <Link to="/">Investigation Workbench</Link>
          <Link to="/overview">Security Overview</Link>
          <Link to="/queue">Incident Queue</Link>
          <div className="spacer" />
          <div className="whoami muted">
            {session.role} · {session.orgId}
          </div>
          <button
            className="link-btn"
            onClick={() => {
              logout();
              setAuthed(false);
            }}
          >
            Sign out
          </button>
        </nav>
        <main className="content">
          <Routes>
            <Route path="/" element={<Workbench />} />
            <Route path="/overview" element={<Overview />} />
            <Route path="/queue" element={<IncidentQueue />} />
            <Route path="/incidents/:id" element={<Investigation />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
