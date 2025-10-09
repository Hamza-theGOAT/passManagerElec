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
  const [editingPassword, setEditingPassword] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showChangePassword, setShowChangePassword] = useState(false);

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

    window.api.onPasswordUpdated((data) => {
      if (data.success) {
        window.api.getAllPasswords();
        setEditingPassword(null);
      }
    });

    window.api.onPasswordDeleted((data) => {
      if (data.success) {
        window.api.getAllPasswords();
      }
    });

    window.api.onShowChangePassword(() => {
      setShowChangePassword(true);
    });

    // Cleanup
    return () => {
      window.api.removeListener("password:list");
      window.api.removeListener("password:added");
      window.api.removeListener("password:updated");
      window.api.removeListener("password:deleted");
      window.api.removeListener("show-change-password");
    };
  }, []);

  const handleLogout = () => {
    window.api.logout();
    onLogout();
  };

  // Filter passwords based on search query
  const filteredPasswords = passwords.filter((password) => {
    const query = searchQuery.toLowerCase();
    return (
      password.title.toLowerCase().includes(query) ||
      password.username.toLowerCase().includes(query)
    );
  });

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🔐 My Passwords</h1>
        <div className="search-bar">
          <input
            type="text"
            placeholder="🔍 Search passwords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => setShowAddForm(true)}>
            + Add Password
          </button>
          <button className="btn-secondary" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>

      {(showAddForm || editingPassword) && (
        <PasswordForm
          password={editingPassword}
          onClose={() => {
            setShowAddForm(false);
            setEditingPassword(null);
          }}
        />
      )}

      {showChangePassword && (
        <ChangeMasterPasswordModal
          onClose={() => setShowChangePassword(false)}
        />
      )}

      <div className="passwords-list">
        {passwords.length === 0 ? (
          <div className="empty-state">
            <p>No passwords saved yet.</p>
            <p>Click "Add Password" to get started!</p>
          </div>
        ) : filteredPasswords.length === 0 ? (
          <div className="empty-state">
            <p>No Passwords match your search.</p>
            <p>Try a different keyword.</p>
          </div>
        ) : (
          filteredPasswords.map((password) => (
            <PasswordItem
              key={password.id}
              password={password}
              onEdit={(pwd) => setEditingPassword(pwd)}
              onDelete={(id) => window.api.deletePassword(id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

// Add Password Form Component
function PasswordForm({ password, onClose }) {
  const [formData, setFormData] = useState({
    title: password?.title || "",
    username: password?.username || "",
    password: "",
    url: password?.url || "",
  });

  const [isLoadingPassword, setIsLoadingPassword] = useState(!!password);

  useEffect(() => {
    if (password) {
      // Fetch the real password when editing
      window.api.revealPassword(password.id);

      const handlePasswordRevealed = (data) => {
        if (data.id === password.id) {
          setFormData((prev) => ({
            ...prev,
            password: data.password,
          }));
          setIsLoadingPassword(false);
        }
      };

      window.api.onPasswordRevealed(handlePasswordRevealed);
    }
  }, [password]);

  const isEditing = !!password;

  const handleSubmit = (e) => {
    e.preventDefault();

    if (isEditing) {
      // Update existing password
      console.log("Updating password:", formData);
      window.api.updatePassword({ ...formData, id: password.id });
    } else {
      // Add new password
      console.log("Adding password:", formData);
      window.api.addPassword(formData);
    }
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
        <h2>{isEditing ? "Edit Password" : "Add New Password"}</h2>
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
              {isEditing ? "Update" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Password Item Component
function PasswordItem({ password, onEdit, onDelete }) {
  const [showPassword, setShowPassword] = useState(false);
  const [revealedPassword, setRevealedPassword] = useState("");

  useEffect(() => {
    const handlePasswordRevealed = (data) => {
      console.log("Received password:revealed event:", data);
      if (data.id === password.id) {
        console.log("Setting revealed password:", data.password);
        setRevealedPassword(data.password);
        setShowPassword(true);
      }
    };

    window.api.onPasswordRevealed(handlePasswordRevealed);

    return () => {
      window.api.removeListener("password:revealed");
    };
  }, [password.id]);

  const handleReveal = () => {
    if (!showPassword) {
      window.api.revealPassword(password.id);
    } else {
      setShowPassword(false);
      setRevealedPassword("");
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
        {showPassword && (
          <div className="revealed-password">
            <strong>Password:</strong> {revealedPassword}
          </div>
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
          onClick={() => onEdit(password)}
          title="Edit"
        >
          ✏️
        </button>
        <button
          className="btn-icon"
          onClick={() => onDelete(password.id)}
          title="Delete"
        >
          🗑️
        </button>
      </div>
    </div>
  );
}

// Change Master Password Component
function ChangeMasterPasswordModal({ onClose }) {
  const [formData, setFormData] = useState({
    oldPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    window.api.onChangePasswordSuccess(() => {
      setSuccess(true);
      setError("");
      setTimeout(() => {
        onClose();
      }, 2000);
    });

    window.api.onChangePasswordError((errorMsg) => {
      setError(errorMsg);
    });

    return () => {
      window.api.removeListener("auth:change-password-success");
      window.api.removeListener("auth:change-password-error");
    };
  }, [onClose]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");

    // Validation
    if (!formData.oldPassword) {
      setError("Please enter your current password");
      return;
    }

    if (!formData.newPassword) {
      setError("Please enter a new password");
      return;
    }

    if (formData.newPassword.length < 6) {
      setError("New password must be at least 6 characters");
      return;
    }

    if (formData.newPassword === formData.oldPassword) {
      setError("New password must be different from current password");
      return;
    }

    if (formData.newPassword !== formData.confirmPassword) {
      setError("New passwords do not match");
      return;
    }

    // Send change request
    window.api.changePassword(formData.oldPassword, formData.newPassword);
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
        <h2>Change Master Password</h2>

        {success ? (
          <div className="success-message">
            ✓ Master password changed successfully!
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Current Password</label>
              <input
                type="password"
                name="oldPassword"
                value={formData.oldPassword}
                onChange={handleChange}
                placeholder="Enter current password"
                autoFocus
                required
              />
            </div>

            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                name="newPassword"
                value={formData.newPassword}
                onChange={handleChange}
                placeholder="Enter new password"
                required
              />
            </div>

            <div className="form-group">
              <label>Confirm New Password</label>
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Confirm new password"
                required
              />
            </div>

            {error && <div className="error-message">{error}</div>}

            <div className="form-actions">
              <button type="button" className="btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn-primary">
                Update Password
              </button>
            </div>
          </form>
        )}
      </div>
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
