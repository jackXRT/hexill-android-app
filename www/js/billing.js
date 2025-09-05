// Google Play Billing for Pro upgrade
function initializeBilling() {
  if (typeof store !== 'undefined') {
    // Register the Pro upgrade product
    store.register({
      id: 'hexill_pro_upgrade',
      type: store.CONSUMABLE,
    });

    store.when('hexill_pro_upgrade').approved(function(product) {
      // User purchased Pro upgrade
      upgradeToPro();
      product.finish();
    });

    store.refresh();
  }
}

function purchaseProUpgrade() {
  if (typeof store !== 'undefined') {
    store.order('hexill_pro_upgrade');
  } else {
    alert('Payment system not available');
  }
}

function upgradeToPro() {
  // Update user to Pro status
  hexillAccountType = 'pro';
  localStorage.setItem('hexill_pro', 'true');
  alert('Welcome to Hexill Pro! You now have unlimited access.');
  location.reload();
}

// Check if user already has Pro
function checkProStatus() {
  if (localStorage.getItem('hexill_pro') === 'true') {
    hexillAccountType = 'pro';
  }
}

// Initialize when device is ready
document.addEventListener('deviceready', function() {
  initializeBilling();
  checkProStatus();
}, false);
