const path = require('path');
const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const crypto = require('crypto');
const { error } = require('console');
const { json } = require('stream/consumers');
const fs = require('fs').promises;

const isDev = process.env.NODE_ENV !== 'production';
const isMac = process.platform === 'darwin';

let mainWindow;
let aboutWindow;

// Temporary in-memory storage (will be replaced with encrypted file storage)
let passwordStore = [];
let masterPasswordHash = null; // Will store hashed master password
let isSetupComplete = false;

// File paths
const userDataPath = app.getPath('userData');
const masterPasswordFile = path.join(userDataPath, 'master.enc');
const passwordsFile = path.join(userDataPath, 'passwords.enc');

// Encryption helper functions
function deriveKey(password, salt) {
  // Derive a 32-byte key from password using PBKDF2
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encrypt(text, password) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return salt + iv + encrypted data (all concatenated)
  return salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData, password) {
  const parts = encryptedData.salt(':');
  const salt = Buffer.from(parts[0], 'hex');
  const iv = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];

  const key = deriveKey(password, salt);

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

function hashPassword(password) {
  // Create a hash of the master password for verification
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(password, stored) {
  const parts = stored.split(':');
  const salt = Buffer.from(parts[0], 'hex');
  const hash = Buffer.from(parts[1], 'hex');

  const VerifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return crypto.timingSafeEqual(hash, VerifyHash);
}

// File operations
async function loadMasterPassword() {
  try {
    const data = await fs.readFile(masterPasswordFile, 'utf8');
    return data;
  } catch {
    if (error.code === 'ENOENT') {
      // File doesn't exist - first time setup
      return null;
    }
    throw error;
  }
}

async function saveMasterPassword(hashedPassword) {
  await fs.writeFile(masterPasswordFile, hashedPassword, 'utf8');
}

async function loadPasswords(masterPassword) {
  try {
    const encryptedData = await fs.readFile(passwordsFile, 'utf8');
    const decryptedData = decrypt(encryptedData, masterPassword);
    return JSON.parse(decryptedData);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist - no passwords yet
      return [];
    }
    throw error;
  }
}

async function savePasswords(passwords, masterPassword) {
  const jsonData = JSON.stringify(passwords);
  const encryptedData = encrypt(jsonData, masterPassword);
  await fs.writeFile(passwordsFile, encryptedData, 'utf8');
}

// Main Window - React app handles routing between login and main page
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: isDev ? 1200 : 600,
    height: 700,
    icon: `${__dirname}/renderer/assets/icons/unlocked.png`,
    resizable: isDev,
    webPreferences: {
      nodeIntegration: false,  // Keep false for security
      contextIsolation: true,   // Keep true for security
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // Show devtools automatically if in development
  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  // Load single HTML file - React will handle routing
  // Make sure the path matches your actual file structure
  mainWindow.loadFile(path.join(__dirname, './renderer/index.html'));

  // Remove variable from memory on close
  mainWindow.on('closed', () => (mainWindow = null));
}

// About Window
function createAboutWindow() {
  aboutWindow = new BrowserWindow({
    width: 300,
    height: 300,
    title: 'About Local Pass Manager',
    icon: `${__dirname}/assets/icons/Icon_256x256.png`,
  });

  aboutWindow.loadFile(path.join(__dirname, './renderer/about.html'));
}

// When the app is ready, create the window
app.on('ready', () => {
  createMainWindow();

  // TODO: Check if encrypted file exists

  const mainMenu = Menu.buildFromTemplate(menu);
  Menu.setApplicationMenu(mainMenu);
});

// Menu template
const menu = [
  ...(isMac
    ? [
        {
          label: app.name,
          submenu: [
            {
              label: 'About',
              click: createAboutWindow,
            },
          ],
        },
      ]
    : []),
  {
    role: 'fileMenu',
  },
  ...(!isMac
    ? [
        {
          label: 'Help',
          submenu: [
            {
              label: 'About',
              click: createAboutWindow,
            },
          ],
        },
      ]
    : []),
  ...(isDev
    ? [
        {
          label: 'Developer',
          submenu: [
            { role: 'reload' },
            { role: 'forcereload' },
            { type: 'separator' },
            { role: 'toggledevtools' },
          ],
        },
      ]
    : []),
];

// IPC Handlers for password manager functionality

// Handle login verification
ipcMain.on('auth:login', (e, masterPassword) => {
  // TODO: Verify master password against stored hash
  console.log('Login attempt');
  console.log('Stored master password:', masterPasswordHash);
  console.log('Entered password:', masterPassword);
  console.log('isSetupComplete:', isSetupComplete);
  
  // Simulate verification (replace with actual verification)
  const isValid = masterPasswordHash === masterPassword; // Replace with: verifyMasterPassword(masterPassword)
  
  if (isValid) {
    // Send success - React will handle navigation
    mainWindow.webContents.send('auth:login-success');
  } else {
    console.log('Login failed - passwords do not match');
    mainWindow.webContents.send('auth:login-error', 'Invalid master password');
  }
});

// Handle initial setup (first time creating master password)
ipcMain.on('auth:setup', (e, masterPassword) => {
  // TODO: Hash and store master password
  console.log('Setup master password');

  masterPasswordHash = masterPassword;
  isSetupComplete = true;
  
  console.log('Setup complete');
  console.log('Stored master password:', masterPasswordHash);
  console.log('isSetupComplete:', isSetupComplete);
  
  // Simulate setup
  mainWindow.webContents.send('auth:setup-success');
});

// Check if master password exists (first run check)
ipcMain.on('auth:check-setup', (e) => {
  // TODO: Check if master password is already set
  // const isSetup = false; // Replace with actual check
  
  console.log('Check setup called, isSetup:', isSetupComplete);
  mainWindow.webContents.send('auth:setup-status', { isSetup: isSetupComplete });
});

// Handle logout
ipcMain.on('auth:logout', () => {
  console.log('Logout called');
  // Clear any in-memory data
  // React will handle navigation back to login
  mainWindow.webContents.send('auth:logout-success');
});

// Handle password operations (CRUD)
ipcMain.on('password:add', (e, passwordData) => {
  // TODO: Encrypt and store password
  console.log('Add password:', passwordData);
  
  // Simulate success
  const newPassword = {
    id: Date.now(),
    ...passwordData,
    createdAt: new Date().toISOString()
  };

  passwordStore.push(newPassword);
  
  console.log('Password added successfully. Total passwords:', passwordStore.length);
  console.log('Full passwordStore:', JSON.stringify(passwordStore, null, 2));

  mainWindow.webContents.send('password:added', { success: true, password: newPassword });
});

ipcMain.on('password:get-all', (e) => {
  // TODO: Decrypt and retrieve all passwords
  console.log('Get all passwords. Count:', passwordStore.length);
  console.log('PasswordStore contents:', JSON.stringify(passwordStore, null, 2));

  // Returna all passwords (with actual passwords masked)
  const maskedPasswords = passwordStore.map(pwd => ({
    ...pwd,
    password: '••••••••'
  }));
  
  console.log('PasswordStore contents:', JSON.stringify(maskedPasswords, null, 2));
  mainWindow.webContents.send('password:list', maskedPasswords);
});

ipcMain.on('password:update', (e, passwordData) => {
  // TODO: Update encrypted password
  console.log('Update password:', passwordData);
  
  mainWindow.webContents.send('password:updated', { success: true, password: passwordData });
});

ipcMain.on('password:delete', (e, passwordId) => {
  // TODO: Delete password entry
  console.log('Delete password:', passwordId);
  
  mainWindow.webContents.send('password:deleted', { success: true, id: passwordId });
});

// Handle password visibility toggle (decrypt for viewing)
ipcMain.on('password:reveal', (e, passwordId) => {
  // TODO: Decrypt and return actual password
  console.log('Reveal password:', passwordId);
  
  // Simulate decryption
  const password = passwordStore.find(p => p.id === passwordId);
  if (password) {
    console.log('Password revealed');
    mainWindow.webContents.send('password:revealed', {
      id: passwordId,
      password: password.password
    });
  } else {
    console.log('Password not found');
  }
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (!isMac) app.quit();
});

// Open a window if none are open (macOS)
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
});