const { useState, useEffect } = React;

// Login Component
function Login({ onLoginSuccess }) {
  const [masterPassword, setMasterPassword] = useState("");
  const [error, setError] = useState("");
  const [isSetup, setIsSetup] = useState(null);

  useEffect(() => {
    // Check if master password is already set up
    window.api.checkSetup();

    window.api.onSetupStatus((data) => {
      setIsSetup(data.isSetup);
    });

    window.api.onLoginSuccess(() => {
      onLoginSuccess();
    });

    window.api.onLoginError((errorMsg) => {
      setError(errorMsg);
    });

    window.api.onSetupSuccess(() => {
      onLoginSuccess();
    });

    // Cleanup
    return () => {
      window.api.removeListener("auth:setup-status");
      window.api.removeListener("auth:login-success");
      window.api.removeListener("auth:login-error");
      window.api.removeListener("auth:setup-success");
    };
  }, [onLoginSuccess]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");

    if (!masterPassword) {
      setError("Please enter your master password");
      return;
    }

    if (isSetup) {
      // Login with existing master password
      window.api.login(masterPassword);
    } else {
      // First time setup
      window.api.setupMasterPassword(masterPassword);
    }
  };

  if (isSetup === null) {
    return (
      <div className="login-container">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>🔐 Local Pass Manager</h1>
        <h2>{isSetup ? "Welcome Back" : "First Time Setup"}</h2>
        <p className="subtitle">
          {isSetup
            ? "Enter your master password to unlock your vault"
            : "Create a master password to secure your vault"}
        </p>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="masterPassword">Master Password</label>
            <input
              type="password"
              id="masterPassword"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              placeholder="Enter master password"
              autoFocus
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" className="btn-primary">
            {isSetup ? "Unlock" : "Create Vault"}
          </button>
        </form>

        {!isSetup && (
          <div className="info-box">
            <strong>⚠️ Important:</strong> Remember this password! It cannot be
            recovered if lost.
          </div>
        )}
      </div>
    </div>
  );
}

// Main Dashboard Component
function Dashboard({ onLogout }) {
  const [passwords, setPasswords] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);

  useEffect(() => {
    // Load passwords on mount
    window.api.getAllPasswords();

    window.api.onPasswordList((passwordList) => {
      setPasswords(passwordList);
    });

    window.api.onPasswordAdded((data) => {
      if (data.success) {
        window.api.getAllPasswords();
        setShowAddForm(false);
      }
    });

    window.api.onPasswordDeleted((data) => {
      if (data.success) {
        setPasswords(passwords.filter((p) => p.id !== data.id));
      }
    });

    // Cleanup
    return () => {
      window.api.removeListener("password:list");
      window.api.removeListener("password:added");
      window.api.removeListener("password:deleted");
    };
  }, []);

  const handleLogout = () => {
    window.api.logout();
    onLogout();
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🔐 My Passwords</h1>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => setShowAddForm(true)}>
            + Add Password
          </button>
          <button className="btn-secondary" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>

      {showAddForm && <AddPasswordForm onClose={() => setShowAddForm(false)} />}

      <div className="passwords-list">
        {passwords.length === 0 ? (
          <div className="empty-state">
            <p>No passwords saved yet.</p>
            <p>Click "Add Password" to get started!</p>
          </div>
        ) : (
          passwords.map((password) => (
            <PasswordItem
              key={password.id}
              password={password}
              onDelete={(id) => window.api.deletePassword(id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

// Add Password Form Component
function AddPasswordForm({ onClose }) {
  const [formData, setFormData] = useState({
    title: "",
    username: "",
    password: "",
    url: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    window.api.addPassword(formData);
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Add New Password</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Title</label>
            <input
              type="text"
              name="title"
              value={formData.title}
              onChange={handleChange}
              placeholder="e.g., Gmail, GitHub"
              required
            />
          </div>

          <div className="form-group">
            <label>Username/Email</label>
            <input
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="username or email"
              required
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="password"
              required
            />
          </div>

          <div className="form-group">
            <label>URL (optional)</label>
            <input
              type="url"
              name="url"
              value={formData.url}
              onChange={handleChange}
              placeholder="https://example.com"
            />
          </div>

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-primary">
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Password Item Component
function PasswordItem({ password, onDelete }) {
  const [showPassword, setShowPassword] = useState(false);
  const [revealedPassword, setRevealedPassword] = useState("");

  const handleReveal = () => {
    if (!showPassword) {
      window.api.revealPassword(password.id);
      window.api.onPasswordRevealed((data) => {
        if (data.id === password.id) {
          setRevealedPassword(data.password);
          setShowPassword(true);
        }
      });
    } else {
      setShowPassword(false);
    }
  };

  return (
    <div className="password-item">
      <div className="password-info">
        <h3>{password.title}</h3>
        <p className="username">{password.username}</p>
        {password.url && (
          <a
            href={password.url}
            target="_blank"
            rel="noopener noreferrer"
            className="url"
          >
            {password.url}
          </a>
        )}
      </div>

      <div className="password-actions">
        <button
          className="btn-icon"
          onClick={handleReveal}
          title="Show password"
        >
          {showPassword ? "🙈" : "👁️"}
        </button>
        <button
          className="btn-icon"
          onClick={() => onDelete(password.id)}
          title="Delete"
        >
          🗑️
        </button>
      </div>

      {showPassword && (
        <div className="revealed-password">
          <strong>Password:</strong> {revealedPassword}
        </div>
      )}
    </div>
  );
}

// Main App Component
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  return (
    <div className="app">
      {isAuthenticated ? (
        <Dashboard onLogout={() => setIsAuthenticated(false)} />
      ) : (
        <Login onLoginSuccess={() => setIsAuthenticated(true)} />
      )}
    </div>
  );
}

// Render the app
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
