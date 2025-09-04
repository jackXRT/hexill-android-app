// ==========================================
// HEXILL Ultimate Scanner - Plan-Based Version
// ==========================================

// Global user state
let hexillUser = null;
let hexillAccountType = 'free'; // Default to free

// API keys for services
const API_KEYS = {
  ETHERSCAN: '25I5W4JWTAVHTEVYNNQJW6XZMIPBYIBBBB',
  BLOCKCYPHER: '60eed12249d94d3cb76739032fd6e84f',
  VIRUSTOTAL: '95ac42a658c1268ab36b879c969244b796202eccc523e026c017b32b756964bb'
};

// Scan types
const SCAN_TYPES = {
  BTC_TX: 'Bitcoin Transaction',
  BTC_ADDRESS: 'Bitcoin Address',
  ETH_TX: 'Ethereum Transaction',
  ETH_ADDRESS: 'Ethereum Address',
  ETH_CONTRACT: 'Smart Contract',
  MD5: 'MD5 Hash',
  SHA1: 'SHA-1 Hash',
  SHA256: 'SHA-256 Hash',
  SHA512: 'SHA-512 Hash',
  KECCAK256: 'Keccak-256 Hash',
  IPFS_CID: 'IPFS Content',
  URL: 'Web URL',
  UNKNOWN: 'Unknown'
};

// BTC to USD conversion rate (will be fetched from API)
let btcToUsdRate = 0;

// Plan-based user management
const hexillAuth = {
  user: null,
  accountType: 'free',
  expiryDate: null,
  
  async checkAuth() {
    try {
      // Check if Firebase user data is available from HTML
      if (window.currentFirebaseUser) {
        console.log('🔥 Firebase user found:', window.currentFirebaseUser.email);
        console.log('🔥 Account type:', window.currentFirebaseUser.accountType);
        console.log('🔥 Expires:', window.currentFirebaseUser.expiryDate);
        
        this.user = window.currentFirebaseUser;
        this.accountType = window.currentFirebaseUser.accountType;
        this.expiryDate = window.currentFirebaseUser.expiryDate;
        hexillAccountType = this.accountType;
        
        return this.user;
      }
      
      // Check if Firebase auth is available
      if (window.firebaseAuth && window.firebaseAuth.currentUser) {
        const user = window.firebaseAuth.currentUser;
        console.log('🔥 Direct Firebase user:', user.email);
        
        // Fetch user plan from Firestore using email as document ID
        if (window.firebaseDb) {
          try {
            const { doc, getDoc } = await import("https://www.gstatic.com/firebasejs/12.0.0/firebase-firestore.js");
            const userDocRef = doc(window.firebaseDb, "users", user.email);
            const docSnap = await getDoc(userDocRef);

            if (docSnap.exists()) {
              const userData = docSnap.data();
              console.log('🔥 Firestore user data:', userData);
              
              // Check if Pro plan is still valid
              const today = new Date();
              const expiry = userData.expiryDate ? new Date(userData.expiryDate) : null;
              
              let accountType = 'free'; // Default
              
              if (userData.accountType === 'pro') {
                if (expiry && today <= expiry) {
                  accountType = 'pro';
                  console.log('✅ Pro plan active until:', userData.expiryDate);
                } else {
                  accountType = 'free';
                  console.log('⚠️ Pro plan expired on:', userData.expiryDate);
                }
              }
              
              this.accountType = accountType;
              this.expiryDate = userData.expiryDate;
              hexillAccountType = accountType;
              
            } else {
              console.log('❌ No user record found in Firestore for:', user.email);
              this.accountType = 'free';
              hexillAccountType = 'free';
            }
          } catch (error) {
            console.error('❌ Error fetching user plan:', error);
            this.accountType = 'free';
            hexillAccountType = 'free';
          }
        }
        
        this.user = user;
        return this.user;
      }
      
      console.log('⚠️ No Firebase user detected, checking session storage');
      
      // Fallback to session storage for testing
      const userData = sessionStorage.getItem('hexill_user_data');
      if (userData) {
        const user = JSON.parse(userData);
        this.user = user;
        this.accountType = user.accountType || 'free';
        this.expiryDate = user.expiryDate || null;
        hexillAccountType = this.accountType;
        console.log('👤 Session user found:', user.email, 'Account:', this.accountType);
        return user;
      }
    } catch (e) {
      console.log('❌ Error in checkAuth:', e);
    }
    
    console.log('👤 No user found, defaulting to free account');
    hexillAccountType = 'free';
    return null;
  },
  
  setUser(email, accountType = 'free', expiryDate = null) {
    const user = { email, accountType, expiryDate, timestamp: Date.now() };
    sessionStorage.setItem('hexill_user_data', JSON.stringify(user));
    this.user = user;
    this.accountType = accountType;
    this.expiryDate = expiryDate;
    hexillAccountType = accountType;
    console.log('📱 User set:', email, '→', accountType.toUpperCase(), expiryDate ? `(expires: ${expiryDate})` : '');
  }
};

// ======================
// 💰 BTC TO USD CONVERSION
// ======================

async function fetchBTCPrice() {
  try {
    // Try multiple BTC price APIs
    const apis = [
      'https://api.coinbase.com/v2/exchange-rates?currency=BTC',
      'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd'
    ];
    
    for (const apiUrl of apis) {
      try {
        const response = await fetch(apiUrl);
        const data = await response.json();
        
        if (apiUrl.includes('coinbase')) {
          btcToUsdRate = parseFloat(data.data.rates.USD);
        } else if (apiUrl.includes('coingecko')) {
          btcToUsdRate = data.bitcoin.usd;
        }
        
        if (btcToUsdRate > 0) {
          console.log('💰 BTC price fetched:', btcToUsdRate);
          return btcToUsdRate;
        }
      } catch (apiError) {
        console.warn(`Failed to fetch from ${apiUrl}:`, apiError);
        continue;
      }
    }
    
    // If all APIs fail, use fallback
    throw new Error('All BTC price APIs failed');
    
  } catch (error) {
    console.error('Error fetching BTC price:', error);
    // Fallback to a default rate if API fails
    btcToUsdRate = 45000; // Default fallback
    console.log('💰 Using fallback BTC price:', btcToUsdRate);
    return btcToUsdRate;
  }
}

function convertBTCToUSD(btcAmount) {
  return (btcAmount * btcToUsdRate).toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD'
  });
}

// ======================
// 🧠 CORE SCANNER FUNCTIONS
// ======================

async function scanHash() {
  const input = document.getElementById('hashInput').value.trim();
  if (!input) return;
  
  showStatus('<div class="scanning-animation"></div>');
  
  try {
    const scanType = detectInputType(input);
    let result;
    
    switch(scanType) {
      case SCAN_TYPES.ETH_TX:
        result = await handleEthereumTx(input);
        break;
      case SCAN_TYPES.BTC_TX:
        result = await handleBitcoinTx(input);
        break;
      case SCAN_TYPES.ETH_ADDRESS:
        result = await handleEthereumAddress(input);
        break;
      case SCAN_TYPES.BTC_ADDRESS:
        result = await handleBitcoinAddress(input);
        break;
      case SCAN_TYPES.IPFS_CID:
        result = handleIPFSContent(input);
        break;
      case SCAN_TYPES.URL:
        result = await handleURL(input);
        break;
      default:
        result = handleCryptographicHash(input, scanType);
    }
    
    showResult(result);
  } catch (e) {
    console.error("Scan error:", e);
    showResult('<div class="result-placeholder">Scan failed. Please try again.</div>');
  } finally {
    showStatus('');
  }
}

// ======================
// 🔍 INPUT DETECTION
// ======================

function detectInputType(input) {
  if (!input) return SCAN_TYPES.UNKNOWN;

  // Ethereum Transaction
  if (/^0x[a-fA-F0-9]{64}$/.test(input)) return SCAN_TYPES.ETH_TX;
  
  // Bitcoin Transaction
  if (/^[a-fA-F0-9]{64}$/.test(input)) return SCAN_TYPES.BTC_TX;
  
  // Ethereum Address
  if (/^0x[a-fA-F0-9]{40}$/.test(input)) return SCAN_TYPES.ETH_ADDRESS;
  
  // Bitcoin Address
  if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}$/.test(input)) return SCAN_TYPES.BTC_ADDRESS;
  
  // IPFS CID
  if (/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[0-9A-Za-z]{50,})$/.test(input)) return SCAN_TYPES.IPFS_CID;
  
  // Hashes
  if (/^[a-fA-F0-9]{32}$/.test(input)) return SCAN_TYPES.MD5;
  if (/^[a-fA-F0-9]{40}$/.test(input)) return SCAN_TYPES.SHA1;
  if (/^[a-fA-F0-9]{64}$/.test(input)) return SCAN_TYPES.SHA256;
  if (/^[a-fA-F0-9]{128}$/.test(input)) return SCAN_TYPES.SHA512;
  
  // URL
  if (/^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/.test(input)) return SCAN_TYPES.URL;
  
  return SCAN_TYPES.UNKNOWN;
}

// ======================
// 🪙 BLOCKCHAIN HANDLERS
// ======================

async function handleEthereumTx(txHash) {
  const [txData, receiptData] = await Promise.all([
    fetchEthereumAPIData(`module=proxy&action=eth_getTransactionByHash&txhash=${txHash}`),
    fetchEthereumAPIData(`module=proxy&action=eth_getTransactionReceipt&txhash=${txHash}`)
  ]);

  const tx = txData.result || {};
  const receipt = receiptData.result || {};
  
  return `
    <div class="result-card ethereum">
      <h3><i class="fab fa-ethereum"></i> Ethereum Transaction</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>Hash:</span>
          <span class="monospace">${txHash}</span>
        </div>
        <div class="data-row">
          <span>From:</span>
          <span class="monospace">${tx.from || 'Unknown'}</span>
        </div>
        <div class="data-row">
          <span>To:</span>
          <span class="monospace">${tx.to || 'Contract Creation'}</span>
        </div>
        <div class="data-row">
          <span>Value:</span>
          <span>${parseInt(tx.value || '0', 16) / 1e18} ETH</span>
        </div>
        <div class="data-row">
          <span>Status:</span>
          <span>${receipt.status === '0x1' ? 'Success' : receipt.status ? 'Failed' : 'Pending'}</span>
        </div>
      </div>
      <button onclick="handleTerminalRedirect('${txHash}', 'ETH_TX')" class="action-btn">
        <i class="fas fa-terminal"></i> Analyze in Terminal
      </button>
    </div>
  `;
}

async function handleEthereumAddress(address) {
  const [balanceData, txData, contractData] = await Promise.all([
    fetchEthereumAPIData(`module=account&action=balance&address=${address}&tag=latest`),
    fetchEthereumAPIData(`module=account&action=txlist&address=${address}&startblock=0&endblock=99999999`),
    fetchEthereumAPIData(`module=contract&action=getabi&address=${address}`)
  ]);

  const isContract = contractData.result !== 'Contract source code not verified';
  const balance = parseInt(balanceData.result || '0') / 1e18;
  const txCount = txData.result?.length || 0;

  return `
    <div class="result-card ${isContract ? 'contract' : 'ethereum'}">
      <h3><i class="fab fa-ethereum"></i> ${isContract ? 'Smart Contract' : 'Ethereum Address'}</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>Address:</span>
          <span class="monospace">${address}</span>
        </div>
        <div class="data-row">
          <span>Balance:</span>
          <span>${balance} ETH</span>
        </div>
        <div class="data-row">
          <span>Transactions:</span>
          <span>${txCount}</span>
        </div>
        ${isContract ? `
        <div class="data-row">
          <span>Contract:</span>
          <span>Verified</span>
        </div>` : ''}
      </div>
      <button onclick="handleTerminalRedirect('${address}', 'ETH_ADDRESS')" class="action-btn">
        <i class="fas fa-terminal"></i> Analyze in Terminal
      </button>
    </div>
  `;
}

async function handleBitcoinTx(txHash) {
  const data = await fetchBlockcypherData(`btc/main/txs/${txHash}`);
  const btcAmount = (data.total / 1e8);
  const usdValue = convertBTCToUSD(btcAmount);
  
  return `
    <div class="result-card bitcoin">
      <h3><i class="fab fa-bitcoin"></i> Bitcoin Transaction</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>Hash:</span>
          <span class="monospace">${txHash}</span>
        </div>
        <div class="data-row">
          <span>Value:</span>
          <span>${btcAmount.toFixed(8)} BTC (${usdValue})</span>
        </div>
        <div class="data-row">
          <span>Confirmations:</span>
          <span>${data.confirmations || 0}</span>
        </div>
      </div>
      <button onclick="handleTerminalRedirect('${txHash}', 'BTC_TX')" class="action-btn">
        <i class="fas fa-terminal"></i> Analyze in Terminal
      </button>
    </div>
  `;
}

async function handleBitcoinAddress(address) {
  const data = await fetchBlockcypherData(`btc/main/addrs/${address}/balance`);
  const btcAmount = (data.balance / 1e8);
  const usdValue = convertBTCToUSD(btcAmount);
  
  return `
    <div class="result-card bitcoin">
      <h3><i class="fab fa-bitcoin"></i> Bitcoin Address</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>Address:</span>
          <span class="monospace">${address}</span>
        </div>
        <div class="data-row">
          <span>Balance:</span>
          <span>${btcAmount.toFixed(8)} BTC (${usdValue})</span>
        </div>
        <div class="data-row">
          <span>Transactions:</span>
          <span>${data.n_tx}</span>
        </div>
      </div>
      <button onclick="handleTerminalRedirect('${address}', 'BTC_ADDRESS')" class="action-btn">
        <i class="fas fa-terminal"></i> Analyze in Terminal
      </button>
    </div>
  `;
}

// ======================
// 🔐 CRYPTOGRAPHIC HASHES
// ======================

function handleCryptographicHash(hash, type = null) {
  type = type || detectInputType(hash);
  const hashInfo = {
    [SCAN_TYPES.MD5]: {
      bits: 128,
      security: 'Insecure (collisions found)',
      icon: 'fas fa-fingerprint'
    },
    [SCAN_TYPES.SHA1]: {
      bits: 160,
      security: 'Broken (theoretical collisions)',
      icon: 'fas fa-shield-alt'
    },
    [SCAN_TYPES.SHA256]: {
      bits: 256,
      security: 'Secure (used in Bitcoin)',
      icon: 'fas fa-lock'
    },
    [SCAN_TYPES.SHA512]: {
      bits: 512,
      security: 'Highly Secure',
      icon: 'fas fa-lock'
    },
    [SCAN_TYPES.KECCAK256]: {
      bits: 256,
      security: 'Secure (used in Ethereum)',
      icon: 'fas fa-lock'
    }
  }[type] || {
    bits: hash.length * 4,
    security: 'Unknown',
    icon: 'fas fa-question-circle'
  };

  return `
    <div class="result-card hash">
      <h3><i class="${hashInfo.icon}"></i> ${type}</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>Hash:</span>
          <span class="monospace">${hash}</span>
        </div>
        <div class="data-row">
          <span>Length:</span>
          <span>${hashInfo.bits} bits</span>
        </div>
        <div class="data-row">
          <span>Security:</span>
          <span class="${hashInfo.security.includes('Secure') ? 'secure' : 'insecure'}">
            ${hashInfo.security}
          </span>
        </div>
      </div>
      <button onclick="openRealTerminal('${hash}', '${type}')" class="action-btn">
        <i class="fas fa-terminal"></i> Crack in Terminal
      </button>
    </div>
  `;
}

// ======================
// 🌐 IPFS & URL HANDLING
// ======================

function handleIPFSContent(cid) {
  const gateways = [
    `https://ipfs.io/ipfs/${cid}`,
    `https://cloudflare-ipfs.com/ipfs/${cid}`,
    `https://${cid}.ipfs.dweb.link`
  ];

  return `
    <div class="result-card ipfs">
      <h3><i class="fas fa-network-wired"></i> IPFS Content</h3>
      <div class="data-grid">
        <div class="data-row">
          <span>CID:</span>
          <span class="monospace">${cid}</span>
        </div>
        <div class="data-row">
          <span>Gateways:</span>
          <div class="gateway-links">
            ${gateways.map(g => `
              <a href="${g}" target="_blank">${new URL(g).hostname}</a>
            `).join('')}
          </div>
        </div>
      </div>
    </div>
  `;
}

async function handleURL(url) {
  try {
    const domain = new URL(url).hostname;
    let safetyReport = '';
    
    if (API_KEYS.VIRUSTOTAL) {
      safetyReport = `<div class="data-row">
        <span>Safety Check:</span>
        <span id="vt-result">Checking...</span>
      </div>`;
    }

    return `
      <div class="result-card url">
        <h3><i class="fas fa-globe"></i> URL Analysis</h3>
        <div class="data-grid">
          <div class="data-row">
            <span>URL:</span>
            <span class="monospace">${url}</span>
          </div>
          <div class="data-row">
            <span>Domain:</span>
            <span>${domain}</span>
          </div>
          ${safetyReport}
        </div>
        ${API_KEYS.VIRUSTOTAL ? `
        <button onclick="scanURLSafety('${url}')" class="action-btn">
          <i class="fas fa-shield-alt"></i> Check Safety
        </button>
        ` : ''}
      </div>
    `;
  } catch {
    return `
      <div class="result-card url">
        <h3><i class="fas fa-globe"></i> URL Analysis</h3>
        <div class="data-grid">
          <div class="data-row">
            <span>Invalid URL:</span>
            <span class="monospace">${url}</span>
          </div>
        </div>
      </div>
    `;
  }
}

// ======================
// 🦠 VIRUSTOTAL INTEGRATION
// ======================

async function scanURLSafety(url) {
  if (!API_KEYS.VIRUSTOTAL) return;
  
  const domain = new URL(url).hostname;
  const vtResultEl = document.getElementById('vt-result');
  if (vtResultEl) vtResultEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
  
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: {
        'x-apikey': API_KEYS.VIRUSTOTAL
      }
    });
    const data = await response.json();
    
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    
    if (vtResultEl) {
      vtResultEl.innerHTML = malicious > 0 
        ? `<span class="insecure">${malicious} security vendors flagged this</span>`
        : `<span class="secure">No security threats detected</span>`;
    }
  } catch (e) {
    console.error("VirusTotal error:", e);
    if (vtResultEl) vtResultEl.innerHTML = '<span class="warning">Safety check failed</span>';
  }
}

// ======================
// 🛠️ UTILITY FUNCTIONS
// ======================

async function fetchEthereumAPIData(query) {
  const response = await fetch(`https://api.etherscan.io/v2/api?chainid=1&${query}&apikey=${API_KEYS.ETHERSCAN}`);
  return await response.json();
}

async function fetchBlockcypherData(endpoint) {
  const response = await fetch(`https://api.blockcypher.com/v1/${endpoint}?token=${API_KEYS.BLOCKCYPHER}`);
  return await response.json();
}

function showStatus(html) {
  const el = document.getElementById('statusText');
  if (el) el.innerHTML = html;
}

function showResult(html) {
  const el = document.getElementById('result');
  if (el) el.innerHTML = html;
}

// ======================
// 💻 TERMINAL FUNCTIONS
// ======================

function openRealTerminal(hash, type) {
  // Create a form to submit data to terminal.html
  const form = document.createElement('form');
  form.method = 'GET';
  form.action = 't3.html';
  
  const hashInput = document.createElement('input');
  hashInput.type = 'hidden';
  hashInput.name = 'hash';
  hashInput.value = hash;
 form.appendChild(hashInput);
  
  const typeInput = document.createElement('input');
  typeInput.type = 'hidden';
  typeInput.name = 'type';
  typeInput.value = type;
  form.appendChild(typeInput);
  
  document.body.appendChild(form);
  form.submit();
}

function handleTerminalRedirect(input, type) {
  // Check user auth first
  hexillAuth.checkAuth();
  
  // Map constant keys to full strings if needed
  const actualType = SCAN_TYPES[type] || type;
  
  // Define pro types using the actual string values
  const proTypes = [
    "Bitcoin Transaction", 
    "Bitcoin Address",
    "Ethereum Transaction",
    "Ethereum Address"
  ];

  console.log("🔐 Account Type:", hexillAccountType);
  console.log("📝 Input Type:", type, "→", actualType);
  console.log("💎 Is Pro Type?", proTypes.includes(actualType));
  
  if (hexillAuth.expiryDate) {
    console.log("⏰ Plan expires:", hexillAuth.expiryDate);
  }

// Determine redirect based on account type
let redirectFile;
if (proTypes.includes(actualType)) {
  // For BTC/ETH operations, check account type
  redirectFile = hexillAccountType === 'pro' ? 't2.html' : 't1.html';
} else {
  // For non-crypto operations, use basic terminal
  redirectFile = 't1.html';
}

console.log("🚀 Redirecting to:", redirectFile);

// Submit form
const form = document.createElement('form');
form.method = 'GET';

// Use direct file names (they're already renamed to be neutral)
form.action = redirectFile;
  const inputField = document.createElement('input');
  inputField.type = 'hidden';
  inputField.name = 'input';
  inputField.value = input;
  form.appendChild(inputField);

  const typeInput = document.createElement('input');
  typeInput.type = 'hidden';
  typeInput.name = 'type';
  typeInput.value = actualType;
  form.appendChild(typeInput);

  document.body.appendChild(form);
  form.submit();
}

// ======================
// 🔓 HASH CRACKING
// ======================

async function crackHash() {
  const input = document.getElementById('hashInput').value.trim();
  if (!input) return;
  
  showStatus('<div class="scanning-animation"></div>');
  
  try {
    // Detect hash type
    const type = detectInputType(input);
    
    // For cryptographic hashes, open the real terminal
    if ([SCAN_TYPES.MD5, SCAN_TYPES.SHA1, SCAN_TYPES.SHA256, 
         SCAN_TYPES.SHA512, SCAN_TYPES.KECCAK256].includes(type)) {
      openRealTerminal(input, type);
    } 
    // For blockchain items (BTC/ETH), use account-based routing
    else if ([SCAN_TYPES.BTC_TX, SCAN_TYPES.ETH_TX, 
             SCAN_TYPES.BTC_ADDRESS, SCAN_TYPES.ETH_ADDRESS].includes(type)) {
      handleTerminalRedirect(input, type);
    } 
    // For other types, show message
    else {
      showResult(`
        <div class="result-card">
          <h3><i class="fas fa-exclamation-triangle"></i> Cannot Crack</h3>
          <p>This input type cannot be cracked: ${type}</p>
          <p>Only cryptographic hashes and blockchain items can be analyzed</p>
        </div>
      `);
    }
  } catch (e) {
    console.error("Crack error:", e);
    showResult('<div class="result-placeholder">Crack operation failed. Please try again.</div>');
  } finally {
    showStatus('');
  }
}

// ======================
// 🚀 INITIALIZATION
// ======================

// Check for persistent test account on load
function checkTestAccount() {
  const testAccount = localStorage.getItem('hexill_temp_account');
  if (testAccount) {
    const expiryDate = testAccount === 'pro' ? '2025-12-31' : null;
    hexillAuth.setUser('test@hexill.com', testAccount, expiryDate);
    console.log('🔄 Restored test account:', testAccount.toUpperCase());
  }
}

async function initScanner() {
  // Wait for Firebase auth to be ready first
  let attempts = 0;
  while (!window.currentFirebaseUser && !window.hexillAccountType && attempts < 10) {
    console.log('⏳ Waiting for Firebase auth to load... attempt', attempts + 1);
    await new Promise(resolve => setTimeout(resolve, 500)); // Wait 500ms
    attempts++;
  }
  
  // Check for persistent test account first
  checkTestAccount();
  
  // Initialize user auth (simple approach) - make it async
  await hexillAuth.checkAuth();
  
  // Fetch BTC price
  await fetchBTCPrice();
  
  const scanBtn = document.getElementById('scan-btn');
  const crackBtn = document.getElementById('crack-btn');
  const hashInput = document.getElementById('hashInput');
  
  if (scanBtn) scanBtn.addEventListener('click', scanHash);
  if (crackBtn) crackBtn.addEventListener('click', crackHash);
  if (hashInput) {
    hashInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') scanHash();
    });
  }
  
  console.log('🚀 Scanner initialized! Final account type:', hexillAccountType);
  if (hexillAuth.expiryDate) {
    console.log('📅 Plan expires:', hexillAuth.expiryDate);
  }
}

// Make functions available globally
window.scanHash = scanHash;
window.crackHash = crackHash;
window.scanURLSafety = scanURLSafety;
window.openRealTerminal = openRealTerminal;
window.handleTerminalRedirect = handleTerminalRedirect;

// Add helper functions to test pro account (with expiry dates)
window.testProAccount = function() {
  const expiryDate = '2025-12-31'; // Set expiry to end of 2025
  hexillAuth.setUser('test@hexill.com', 'pro', expiryDate);
  // Also set in localStorage for persistence across page reloads
  localStorage.setItem('hexill_temp_account', 'pro');
  console.log('✅ Set to PRO account for testing (expires:', expiryDate + ')');
  location.reload(); // Reload to apply changes
};

window.testFreeAccount = function() {
  hexillAuth.setUser('test@hexill.com', 'free', null);
  // Also set in localStorage for persistence across page reloads
  localStorage.setItem('hexill_temp_account', 'free');
  console.log('✅ Set to FREE account for testing');
  location.reload(); // Reload to apply changes
};

window.testExpiredAccount = function() {
  const expiredDate = '2024-01-01'; // Expired date
  hexillAuth.setUser('test@hexill.com', 'pro', expiredDate);
  localStorage.setItem('hexill_temp_account', 'pro');
  console.log('✅ Set to EXPIRED PRO account for testing (expired:', expiredDate + ')');
  location.reload(); // Should show as free due to expiry
};

// Helper to test with real Firebase user
window.testFirebaseUser = function() {
  if (window.firebaseAuth && window.firebaseAuth.currentUser) {
    console.log('🔥 Current Firebase user:', window.firebaseAuth.currentUser.email);
    hexillAuth.checkAuth(); // Re-check auth to get latest data
  } else {
    console.log('❌ No Firebase user signed in');
  }
};

// Helper to debug current state
window.debugAccountState = function() {
  console.log('=== ACCOUNT DEBUG ===');
  console.log('hexillAccountType:', hexillAccountType);
  console.log('hexillAuth.accountType:', hexillAuth.accountType);
  console.log('hexillAuth.expiryDate:', hexillAuth.expiryDate);
  console.log('window.currentFirebaseUser:', window.currentFirebaseUser);
  console.log('window.hexillAccountType:', window.hexillAccountType);
  console.log('window.firebaseAuth:', window.firebaseAuth);
  console.log('window.firebaseAuth.currentUser:', window.firebaseAuth ? window.firebaseAuth.currentUser : 'No auth');
  console.log('Test account in localStorage:', localStorage.getItem('hexill_temp_account'));
  console.log('Session data:', sessionStorage.getItem('hexill_user_data'));
  console.log('==================');
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initScanner);
} else {
  initScanner();
}
