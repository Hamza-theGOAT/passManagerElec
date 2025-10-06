const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('api', {
  // Authentication
  login: (masterPassword) => ipcRenderer.send('auth:login', masterPassword),
  setupMasterPassword: (masterPassword) => ipcRenderer.send('auth:setup', masterPassword),
  checkSetup: () => ipcRenderer.send('auth:check-setup'),
  logout: () => ipcRenderer.send('auth:logout'),
  
  onLoginSuccess: (callback) => ipcRenderer.on('auth:login-success', callback),
  onLoginError: (callback) => ipcRenderer.on('auth:login-error', (event, error) => callback(error)),
  onSetupSuccess: (callback) => ipcRenderer.on('auth:setup-success', callback),
  onSetupStatus: (callback) => ipcRenderer.on('auth:setup-status', (event, data) => callback(data)),
  onLogoutSuccess: (callback) => ipcRenderer.on('auth:logout-success', callback),
  
  // Password CRUD operations
  addPassword: (passwordData) => ipcRenderer.send('password:add', passwordData),
  getAllPasswords: () => ipcRenderer.send('password:get-all'),
  updatePassword: (passwordData) => ipcRenderer.send('password:update', passwordData),
  deletePassword: (passwordId) => ipcRenderer.send('password:delete', passwordId),
  revealPassword: (passwordId) => ipcRenderer.send('password:reveal', passwordId),
  
  // Listen for password operations responses
  onPasswordAdded: (callback) => ipcRenderer.on('password:added', (event, data) => callback(data)),
  onPasswordList: (callback) => ipcRenderer.on('password:list', (event, passwords) => callback(passwords)),
  onPasswordUpdated: (callback) => ipcRenderer.on('password:updated', (event, data) => callback(data)),
  onPasswordDeleted: (callback) => ipcRenderer.on('password:deleted', (event, data) => callback(data)),
  onPasswordRevealed: (callback) => ipcRenderer.on('password:revealed', (event, data) => callback(data)),
  
  // Clean up listeners to prevent memory leaks
  removeListener: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  },
  
  // Remove specific listener
  removeSpecificListener: (channel, callback) => {
    ipcRenderer.removeListener(channel, callback);
  }
});