const path = require('path');
const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const crypto = require('crypto');
const { error, count } = require('console');
const { json } = require('stream/consumers');
const { type } = require('os');
const { execPath } = require('process');
const fs = require('fs').promises;

const isDev = process.env.NODE_ENV !== 'production';
const isMac = process.platform === 'darwin';

let mainWindow;
let aboutWindow;

// Temporary in-memory storage (will be replaced with encrypted file storage)
let passwordStore = [];
let masterPasswordHash = null; // Will store hashed master password
let isSetupComplete = false;
let currentMasterPassword = null;

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
  const parts = encryptedData.split(':');
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
app.on('ready', async () => {
  createMainWindow();

  // Check if master password file exists
  try {
    const storedHash = await loadMasterPassword();
    if (storedHash) {
      isSetupComplete = true;
      masterPasswordHash = storedHash;
      console.log('Master password file found - setup complete');
    } else {
      console.log('No Master password file - first time setup');
    }
  } catch (error) {
    console.error('Error loading master password:', error);
  }

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
    label: 'File',
    submenu: [
      {
        label: 'Change Master Password',
        click: () => {
          mainWindow.webContents.send('show-change-password');
        }
      },
      { type: 'separator' },
      {
        label: 'Export Passwords',
        click: () => {
          mainWindow.webContents.send('export-passwords');
        }
      },
      { type: 'separator' },
      {
        label: 'Import Passwords',
        click: () => {
          mainWindow.webContents.send('import-passwords');
        }
      },
      { type: 'separator' },
      {
        label: 'Delete All Entries',
        click: () => {
          mainWindow.webContents.send('delete-all-passwords');
        }
      },
      { type: 'separator' },
      { role: 'quit' }
    ]
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
ipcMain.on('auth:login', async (e, masterPassword) => {
  console.log('Login attempt');
  
  try {
    // Verify password against stored hash
    const isValid = verifyPassword(masterPassword, masterPasswordHash);
    
    if (isValid) {
      console.log('Password verified - loading passwords');

      currentMasterPassword = masterPassword;
      
      // Load encrypted passwords
      passwordStore = await loadPasswords(masterPassword);
      console.log('Loaded passwords:', passwordStore.length);
      
      mainWindow.webContents.send('auth:login-success');
    } else {
      console.log('Login failed - invalid password');
      mainWindow.webContents.send('auth:login-error', 'Invalid master password');
    }
  } catch (error) {
    console.error('Login error:', error);
    mainWindow.webContents.send('auth:login-error', 'Failed to decrypt vault');
  }
});

// Handle initial setup (first time creating master password)
ipcMain.on('auth:setup', async (e, masterPassword) => {
  // Hash and store master password
  console.log('Setup master password');

  try {
    // Hash the master password
    const hashedPassword = hashPassword(masterPassword);

    currentMasterPassword = masterPassword;

    // Save to file
    await saveMasterPassword(hashedPassword);

    // Update state
    masterPasswordHash = hashedPassword;
    isSetupComplete = true;

    // Initialize empty password store
    passwordStore = [];
    await savePasswords(passwordStore, masterPassword);

    console.log('Setup complete - files created');
    mainWindow.webContents.send('auth:setup-success');
  } catch (error) {
    console.error('Setup error:', error);
    mainWindow.webContents.send('auth:login-error', 'Failed to create vault');
  }
});

// Check if master password exists (first run check)
ipcMain.on('auth:check-setup', (e) => {
  // TODO: Check if master password is already set
  // const isSetup = false; // Replace with actual check
  
  console.log('Check setup called, isSetup:', isSetupComplete);
  mainWindow.webContents.send('auth:setup-status', { isSetup: isSetupComplete });
});

// Handle master password change
ipcMain.on('auth:change-password', async (e, { oldPassword, newPassword }) => {
  console.log('Change master password request');

  try {
    // Verify old password
    const isValid = verifyPassword(oldPassword, masterPasswordHash);

    if (!isValid) {
      console.log('Old password incorrect');
      mainWindow.webContents.send('auth:change-password-error', 'Current password is incorrect');
      return;
    }

    console.log('Old password verified - changing to new password');

    // Hash new password
    const newHashedPassword = hashPassword(newPassword);

    // Re-encrypt all passwords with new master password
    const currentPasswords = passwordStore;

    // Save new master password hash
    await saveMasterPassword(newHashedPassword);

    // Re-encrypt passwords with new master password
    await savePasswords(currentPasswords, newPassword);

    // Update in-memory values
    masterPasswordHash = newHashedPassword;
    currentMasterPassword = newPassword;

    console.log('Master password changed successfully');
    mainWindow.webContents.send('auth:change-password-success');

  } catch (error) {
    console.error('Change password error:', error);
    mainWindow.webContents.send('auth:change-password-error', 'Failed to change password');
  }
});

// Handle password export
ipcMain.on('password:export', async (e) => {
  console.log('Export passwords request received');

  try {
    const exportsDir = path.join(__dirname, 'assets', 'exports');
    // TODO: Create exports directory if it doesn't exist

    const exportPath = path.join(exportsDir, 'passKeys.json');

    // Export all passwords (unencrypted - WARN USER!)
    const exportData = {
      exportDate: new Date().toISOString(),
      passwordCount: passwordStore.length,
      passwords: passwordStore
    };

    await fs.writeFile(exportPath, JSON.stringify(exportData, null, 2), 'utf8');

    console.log('Passwords exported to:', exportPath);
    mainWindow.webContents.send('password:export-success', {
      path: exportPath,
      count: passwordStore.length
    });
  } catch (error) {
    console.error('Export error:', error);
    mainWindow.webContents.send('password:export-error', 'Failed to export passwords');
  }
});

// Handle password import
ipcMain.on('password:import', async (e) => {
  console.log('Import passwords request');
  
  try {
    const importPath = path.join(__dirname, 'assets', 'imports', 'passKeys.json');
    console.log('Import path:', importPath);
    
    // Check if file exists
    try {
      await fs.access(importPath);
    } catch (error) {
      console.log('Import file not found');
      mainWindow.webContents.send('password:import-error', 'Import file not found at assets/imports/passKeys.json');
      return;
    }
    
    // Read the import file
    const importData = await fs.readFile(importPath, 'utf8');
    const parsedData = JSON.parse(importData);
    
    console.log('Parsed import data:', parsedData);
    
    // Validate the data structure
    if (!parsedData.passwords || !Array.isArray(parsedData.passwords)) {
      console.log('Invalid import file structure');
      mainWindow.webContents.send('password:import-error', 'Invalid file format: missing passwords array');
      return;
    }
    
    const importedPasswords = parsedData.passwords;
    console.log('Found passwords to import:', importedPasswords.length);
    
    let addedCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;
    
    // Merge logic
    for (const importedPwd of importedPasswords) {
      // Skip if missing required fields
      if (!importedPwd.title || !importedPwd.username || !importedPwd.password) {
        console.log('Skipping invalid entry:', importedPwd);
        skippedCount++;
        continue;
      }
      
      // Find matching entry by ID or username
      const existingIndex = passwordStore.findIndex(
        p => p.id === importedPwd.id || 
        (p.username === importedPwd.username && p.title === importedPwd.title)
      );
      
      if (existingIndex !== -1) {
        // Update existing entry
        console.log('Updating existing password:', importedPwd.title);
        passwordStore[existingIndex] = {
          ...passwordStore[existingIndex],
          ...importedPwd,
          id: passwordStore[existingIndex].id, // Keep original ID
          createdAt: passwordStore[existingIndex].createdAt, // Keep original creation date
          updatedAt: new Date().toISOString() // Add update timestamp
        };
        updatedCount++;
      } else {
        // Add new entry
        console.log('Adding new password:', importedPwd.title);
        const newPassword = {
          ...importedPwd,
          id: importedPwd.id || Date.now() + Math.random(), // Use imported ID or generate new one
          createdAt: importedPwd.createdAt || new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        passwordStore.push(newPassword);
        addedCount++;
      }
    }
    
    // Save to encrypted file
    await savePasswords(passwordStore, currentMasterPassword);
    
    console.log(`Import complete: ${addedCount} added, ${updatedCount} updated, ${skippedCount} skipped`);
    
    mainWindow.webContents.send('password:import-success', {
      added: addedCount,
      updated: updatedCount,
      skipped: skippedCount,
      total: importedPasswords.length
    });
    
  } catch (error) {
    console.error('Import error:', error);
    mainWindow.webContents.send('password:import-error', 'Failed to import passwords: ' + error.message);
  }
});

// Handle logout
ipcMain.on('auth:logout', () => {
  console.log('Logout called');
  // Clear any in-memory data
  // React will handle navigation back to login
  mainWindow.webContents.send('auth:logout-success');
});

// Handle password operations (CRUD)
ipcMain.on('password:add', async (e, passwordData) => {
  // Encrypt and store password
  console.log('Add password:', passwordData);

  try {
    const newPassword = {
      id: Date.now(),
      ...passwordData,
      createdAt: new Date().toISOString()
    };

    passwordStore.push(newPassword);

    
    // TODO: Save to encrypted file (need master password)
    // Save to encrypted file
    await savePasswords(passwordStore, currentMasterPassword);
    console.log('Password added successfully. Total passwords:', passwordStore.length);

    mainWindow.webContents.send('password:added', { success: true, password: newPassword });
  } catch (error) {
    console.error('Add password error:', error);
    mainWindow.webContents.send('password:added', { success: false });
  }
});

ipcMain.on('password:get-all', (e) => {
  // TODO: Decrypt and retrieve all passwords
  console.log('Get all passwords. Count:', passwordStore.length);
  // console.log('PasswordStore contents:', JSON.stringify(passwordStore, null, 2));

  // Returna all passwords (with actual passwords masked)
  const maskedPasswords = passwordStore.map(pwd => ({
    ...pwd,
    password: '••••••••'
  }));
  
  // console.log('PasswordStore contents:', JSON.stringify(maskedPasswords, null, 2));
  mainWindow.webContents.send('password:list', maskedPasswords);
});

ipcMain.on('password:update', async (e, passwordData) => {
  // Update encrypted password
  console.log('Update password:', passwordData);
  
  try {
    const index = passwordStore.findIndex(p => p.id === passwordData.id);
    
    if (index !== -1) {
      // Don't update the password if it's masked (unchanged)
      const updatedData = { ...passwordData };
      if (passwordData.password === '••••••••') {
        // Keep the original password
        updatedData.password = passwordStore[index].password;
      }

      // Update the password entry
      passwordStore[index] = { ...passwordStore[index], ...updatedData };
      
      // Save to encrypted file
      await savePasswords(passwordStore, currentMasterPassword);
      
      console.log('Password updated successfully');
      mainWindow.webContents.send('password:updated', { success: true, password: passwordStore[index] });
    } else {
      console.log('Password not found');
      mainWindow.webContents.send('password:updated', { success: false });
    }
  } catch (error) {
    console.error('Update password error:', error);
    mainWindow.webContents.send('password:updated', { success: false });
  }
});

ipcMain.on('password:delete', async (e, passwordId) => {
  // Delete password entry
  console.log('Delete password:', passwordId);

  try {
    // Find the index of the password to delete
    const index = passwordStore.findIndex(p => p.id === passwordId);

    if (index !== -1) {
      // Remove from array
      passwordStore.splice(index, 1);

      // Save updated list to encrypted file
      await savePasswords(passwordStore, currentMasterPassword);

      console.log('Password deleted. Remaining passwords:', passwordStore.length);
      mainWindow.webContents.send('password:deleted', { success: true, id: passwordId });
    } else {
      console.log('Password not found');
      mainWindow.webContents.send('password:deleted', { success: false });
    }
  } catch (error) {
    console.error('Delete password error:', error);
    mainWindow.webContents.send('password:deleted', { success: false });
  }
});

// Handle password visibility toggle (decrypt for viewing)
ipcMain.on('password:reveal', (e, passwordId) => {
  // TODO: Decrypt and return actual password
  console.log('Reveal password:', passwordId);
  
  // Simulate decryption
  const password = passwordStore.find(p => p.id === passwordId);
  if (password) {
    console.log('Password found:', password.title);
    console.log('Actual password value:', password.password);

    mainWindow.webContents.send('password:revealed', {
      id: passwordId,
      password: password.password
    });
    
    // console.log('Sent password:revealed event with:', password.password);
  } else {
    console.log('Password not found');
  }
});

// Handle delete all passwords
ipcMain.on('password:delete-all', async (e) => {
  console.log('Delete all passwords request');

  try {
    // Clear the password store
    passwordStore = [];

    // Save empty array to encrypted file
    await savePasswords(passwordStore, currentMasterPassword);

    console.log('All passwords deleted successfully');
    mainWindow.webContents.send('password:delete-all-success');
  } catch (error) {
    console.error('Delete all error:', error);
    mainWindow.webContents.send('password:delete-all-error', 'Failed to delete passwords');
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

// Suppress GPU warnings
process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-software-resterizer');