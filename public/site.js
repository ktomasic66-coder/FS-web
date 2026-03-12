/* ===== SITE.JS — Language Toggle + Theme Switcher ===== */

(function() {
  'use strict';

  // ===== TRANSLATIONS =====
  var translations = {
    // Navbar
    'home': { hr: 'Početna', en: 'Home' },
    'gallery': { hr: 'Galerija', en: 'Gallery' },
    'rules': { hr: 'Pravila', en: 'Rules' },
    'statistics': { hr: 'Statistika', en: 'Statistics' },
    'myFarm': { hr: 'Moja Farma', en: 'My Farm' },
    'profile': { hr: 'Profil', en: 'Profile' },
    'admin': { hr: 'Admin', en: 'Admin' },
    'bot': { hr: 'Bot', en: 'Bot' },
    'logout': { hr: 'Logout', en: 'Logout' },
    'login': { hr: 'Login', en: 'Login' },

    // Farm page
    'farmManagement': { hr: 'Upravljanje farmom', en: 'Farm Management' },
    'accountBalance': { hr: 'Stanje računa', en: 'Account Balance' },
    'sendMoney': { hr: '💸 Pošalji novac', en: '💸 Send Money' },
    'targetFarm': { hr: 'Ciljna farma', en: 'Target Farm' },
    'selectFarm': { hr: '-- Odaberi farmu --', en: '-- Select Farm --' },
    'amount': { hr: 'Iznos (€)', en: 'Amount (€)' },
    'queueTransfer': { hr: '📋 Zakaži prijenos', en: '📋 Queue Transfer' },
    'transferNote': { hr: '* Prijenos se izvršava tek nakon sljedećeg spremanja igre (savegame)', en: '* Transfer executes only after the next savegame' },
    'vehicles': { hr: 'Vozila', en: 'Vehicles' },
    'fields': { hr: 'Polja', en: 'Fields' },
    'animals': { hr: 'Životinje', en: 'Animals' },
    'production': { hr: 'Proizvodnja', en: 'Production' },
    'storage': { hr: 'Skladišta', en: 'Storage' },
    'players': { hr: 'Igrači', en: 'Players' },
    'noVehicles': { hr: 'Nema vozila', en: 'No vehicles' },
    'noFields': { hr: 'Nema polja', en: 'No fields' },
    'noAnimals': { hr: 'Nema životinja', en: 'No animals' },
    'noProduction': { hr: 'Nema proizvodnje', en: 'No production' },
    'emptyStorage': { hr: 'Skladište je prazno', en: 'Storage is empty' },

    // Homepage
    'activeFarms': { hr: '🌾 Aktivne Farme', en: '🌾 Active Farms' },
    'balance': { hr: 'Stanje', en: 'Balance' },
    'area': { hr: 'Površina', en: 'Area' },
    'noPlayersOnFarm': { hr: 'Nema igrača na farmi', en: 'No players on farm' },
    'whoAreWe': { hr: 'Tko smo mi', en: 'Who We Are' },
    'news': { hr: 'Novosti', en: 'News' },

    // Filter
    'all': { hr: 'Sve', en: 'All' },
    'lowFuel': { hr: '⛽ Malo goriva', en: '⛽ Low Fuel' },
    'damaged': { hr: '🔧 Oštećeno', en: '🔧 Damaged' },
    'dirty': { hr: '💩 Prljavo', en: '💩 Dirty' },
    'needsAction': { hr: '⚠️ Treba radnju', en: '⚠️ Needs Action' },
    'planted': { hr: '🌱 Zasađeno', en: '🌱 Planted' },
    'empty': { hr: '🚫 Prazno', en: '🚫 Empty' },
    'lowHealth': { hr: '❤️ Slabo zdravlje', en: '❤️ Low Health' },
    'owned': { hr: '✅ Kupljeno', en: '✅ Owned' },
    'notOwned': { hr: '❌ Nije kupljeno', en: '❌ Not Owned' },
    'full': { hr: '📦 Puno (>80%)', en: '📦 Full (>80%)' },
    'low': { hr: '📭 Prazno (<20%)', en: '📭 Empty (<20%)' },
    'searchVehicles': { hr: 'Pretraži vozila...', en: 'Search vehicles...' },
    'searchFields': { hr: 'Pretraži polja...', en: 'Search fields...' },
    'searchAnimals': { hr: 'Pretraži životinje...', en: 'Search animals...' },
    'searchProduction': { hr: 'Pretraži proizvodnju...', en: 'Search production...' },
    'searchStorage': { hr: 'Pretraži skladišta...', en: 'Search storage...' },
    'noResults': { hr: 'Nema rezultata za odabrani filter', en: 'No results for selected filter' },

    // General
    'fuel': { hr: 'Gorivo', en: 'Fuel' },
    'condition': { hr: 'Stanje', en: 'Condition' },
    'dirtiness': { hr: 'Prljavština', en: 'Dirtiness' },
    'health': { hr: 'Zdravlje', en: 'Health' },
    'productivity': { hr: 'Produktivnost', en: 'Productivity' },
    'reproduction': { hr: 'Reprodukcija', en: 'Reproduction' },
    'food': { hr: 'Hrana', en: 'Food' },
    'products': { hr: 'Proizvodi', en: 'Products' },
    'inputs': { hr: 'Ulazi', en: 'Inputs' },
    'outputs': { hr: 'Izlazi', en: 'Outputs' },
    'total': { hr: 'Ukupno', en: 'Total' },
    'contents': { hr: 'Sadržaj', en: 'Contents' },
    'status': { hr: 'Status', en: 'Status' },
    'ownership': { hr: 'Vlasništvo', en: 'Ownership' },
    'yes': { hr: 'Da', en: 'Yes' },
    'no': { hr: 'Ne', en: 'No' },
    'online': { hr: 'Online', en: 'Online' },
    'offline': { hr: 'Offline', en: 'Offline' },
    'played': { hr: 'odigrano', en: 'played' },
    'culture': { hr: 'Kultura', en: 'Crop' },
    'surfaceArea': { hr: 'Površina', en: 'Area' },
    'growth': { hr: 'Rast', en: 'Growth' },
    'plowing': { hr: 'Oranje', en: 'Plowing' },
    'lime': { hr: 'Vapno', en: 'Lime' },
    'fertilizer': { hr: 'Gnojivo', en: 'Fertilizer' },
    'weeds': { hr: 'Korovi', en: 'Weeds' },
    'rolling': { hr: 'Valjanje', en: 'Rolling' },
    'price': { hr: 'Cijena', en: 'Price' },
    'notBought': { hr: 'Nije kupljeno', en: 'Not bought' },
    'fills': { hr: 'Punjenja', en: 'Fill Units' },

    // Login/No farm states
    'noFarmYet': { hr: 'Nemate još kreiranu farmu', en: 'You don\'t have a farm yet' },
    'contactAdmin': { hr: 'Javite se adminu ili kreirajte farmu putem Discord bota da započnete svoje poljoprivredno carstvo.', en: 'Contact an admin or create a farm via the Discord bot to start your farming empire.' },
    'joinDiscord': { hr: 'Pridružite se Discordu', en: 'Join Discord' },
    'loginForFarm': { hr: 'Prijavite se za pristup vašoj farmi', en: 'Log in to access your farm' },
    'loginRequired': { hr: 'Za pregled vaše farme potrebna je prijava putem Discord računa.', en: 'Discord login is required to view your farm.' },
    'loginBtn': { hr: 'Prijava putem Discorda', en: 'Login via Discord' },
  };

  // ===== LANGUAGE =====
  var currentLang = localStorage.getItem('sr-lang') || 'hr';

  function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('sr-lang', lang);
    applyTranslations();
    updateFlagButtons();
  }

  function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(function(el) {
      var key = el.getAttribute('data-i18n');
      if (translations[key] && translations[key][currentLang]) {
        if (el.tagName === 'INPUT' && el.type !== 'submit') {
          el.placeholder = translations[key][currentLang];
        } else if (el.tagName === 'OPTION') {
          el.textContent = translations[key][currentLang];
        } else {
          el.textContent = translations[key][currentLang];
        }
      }
    });
  }

  function updateFlagButtons() {
    document.querySelectorAll('.lang-flag').forEach(function(f) {
      f.classList.toggle('active', f.getAttribute('data-lang') === currentLang);
    });
  }

  // ===== THEME =====
  var currentTheme = localStorage.getItem('sr-theme') || 'green';

  function setTheme(theme) {
    currentTheme = theme;
    localStorage.setItem('sr-theme', theme);
    applyTheme();
    updateThemeButtons();
  }

  function applyTheme() {
    document.body.setAttribute('data-theme', currentTheme);
  }

  function updateThemeButtons() {
    document.querySelectorAll('.theme-btn').forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-theme') === currentTheme);
    });
  }

  // ===== INJECT CONTROLS INTO NAVBAR =====
  function injectControls() {
    var navbar = document.querySelector('.navbar');
    if (!navbar) return;

    var controls = document.createElement('div');
    controls.className = 'site-controls';
    controls.innerHTML =
      '<div class="site-controls-group">' +
        '<button class="lang-flag" data-lang="hr" title="Hrvatski" onclick="window.__setLang(\'hr\')">🇭🇷</button>' +
        '<button class="lang-flag" data-lang="en" title="English" onclick="window.__setLang(\'en\')">🇺🇸</button>' +
      '</div>' +
      '<div class="site-controls-group">' +
        '<button class="theme-btn" data-theme="green" title="Zelena tema" onclick="window.__setTheme(\'green\')"><span style="background:#00ff7a"></span></button>' +
        '<button class="theme-btn" data-theme="gold" title="Zlatna tema" onclick="window.__setTheme(\'gold\')"><span style="background:#ffd700"></span></button>' +
      '</div>';

    navbar.appendChild(controls);
  }

  // Expose for onclick handlers
  window.__setLang = setLanguage;
  window.__setTheme = setTheme;

  // ===== INIT =====
  document.addEventListener('DOMContentLoaded', function() {
    injectControls();
    applyTheme();
    applyTranslations();
    updateFlagButtons();
    updateThemeButtons();
  });

})();
