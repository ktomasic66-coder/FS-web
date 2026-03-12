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

    // Homepage hero
    'heroTitle': { hr: 'Slavonska Ravnica  FS25 Server', en: 'Slavonska Ravnica  FS25 Server' },
    'heroDesc': { hr: 'Realističan Farming Simulator 25 multiplayer s fokusom na ekonomiju, timski rad i dugoročni razvoj farmi.', en: 'Realistic Farming Simulator 25 multiplayer focused on economy, teamwork, and long-term farm development.' },
    'loginDiscord': { hr: 'Prijava putem Discorda', en: 'Login via Discord' },
    'noPosts': { hr: 'Nema objava.', en: 'No posts.' },

    // Homepage sections
    'whoAreWe': { hr: 'Tko smo mi', en: 'Who We Are' },
    'whoAreWeDesc': { hr: 'Slavonska Ravnica je zajednica igrača koji žele kvalitetno i organizirano FS25 iskustvo. Gradimo server gdje trud ima vrijednost, a napredak dolazi kroz rad i suradnju. Kod nas farme imaju priču.', en: 'Slavonska Ravnica is a community of players who want a quality and organized FS25 experience. We build a server where effort has value, and progress comes through work and cooperation. Our farms have a story.' },
    'realisticEcon': { hr: '🚜 Realistična ekonomija', en: '🚜 Realistic Economy' },
    'realisticEconDesc': { hr: 'Balansiran sustav napretka bez preskakanja faza.', en: 'Balanced progression system without skipping phases.' },
    'activeCommunity': { hr: '👥 Aktivna zajednica', en: '👥 Active Community' },
    'activeCommunityDesc': { hr: 'Ozbiljna i organizirana ekipa.', en: 'Serious and organized team.' },
    'events': { hr: '🏆 Eventovi', en: '🏆 Events' },
    'eventsDesc': { hr: 'Redovni izazovi i zajednički projekti.', en: 'Regular challenges and community projects.' },
    'stableServer': { hr: '🛠 Stabilan server', en: '🛠 Stable Server' },
    'stableServerDesc': { hr: 'Optimizirano i dugoročno iskustvo.', en: 'Optimized and long-term experience.' },
    'howToJoin': { hr: 'Kako se pridružiti', en: 'How to Join' },
    'step1': { hr: 'Prijavi se putem Discorda', en: 'Sign in via Discord' },
    'step2': { hr: 'Pridruži se Discordu', en: 'Join our Discord' },
    'step3': { hr: 'Otvori tiket za role PLAYER', en: 'Open a ticket for PLAYER role' },
    'step4': { hr: 'Kreni graditi svoju farmu', en: 'Start building your farm' },
    'readyForMultiplayer': { hr: 'Spreman za ozbiljan multiplayer?', en: 'Ready for serious multiplayer?' },
    'loginToJoin': { hr: 'Prijavi se da bi se pridružio', en: 'Sign in to join' },
    'joinCommunity': { hr: 'Pridruži se zajednici', en: 'Join the community' },

    // Farms overview
    'activeFarms': { hr: '🌾 Aktivne Farme', en: '🌾 Active Farms' },
    'balance': { hr: 'Stanje', en: 'Balance' },
    'area': { hr: 'Površina', en: 'Area' },
    'noPlayersOnFarm': { hr: 'Nema igrača na farmi', en: 'No players on farm' },
    'news': { hr: '📰 Novosti', en: '📰 News' },

    // Farm page
    'farmManagement': { hr: 'Upravljanje farmom', en: 'Farm Management' },
    'accountBalance': { hr: 'Stanje računa', en: 'Account Balance' },
    'sendMoney': { hr: '💸 Pošalji novac', en: '💸 Send Money' },
    'targetFarm': { hr: 'Ciljna farma', en: 'Target Farm' },
    'selectFarm': { hr: '-- Farma --', en: '-- Farm --' },
    'amount': { hr: 'Iznos (€)', en: 'Amount (€)' },
    'queueTransfer': { hr: '📋 Zakaži', en: '📋 Queue' },
    'transferNote': { hr: '* Izvršava se nakon sljedećeg savegame-a', en: '* Executes after the next savegame' },
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

    // Gallery
    'communityMedia': { hr: 'Community media', en: 'Community Media' },
    'galleryTitle': { hr: 'Galerija Zajednice', en: 'Community Gallery' },
    'gallerySubtitle': { hr: 'Podijeli trenutke sa servera, reagiraj na objave i pregledaj komentare u proširenom prikazu.', en: 'Share server moments, react to posts, and view comments in expanded view.' },
    'chooseImage': { hr: 'Odaberi sliku', en: 'Choose image' },
    'imageDesc': { hr: 'Opis slike', en: 'Image description' },
    'publishImage': { hr: 'Objavi sliku', en: 'Publish image' },

    // Profile
    'myProfile': { hr: 'Moj Profil', en: 'My Profile' },
    'noExtraRoles': { hr: 'Nema dodatnih rola', en: 'No additional roles' },

    // Pravila
    'serverPolicy': { hr: 'Server policy', en: 'Server Policy' },
    'rulesNotAdded': { hr: 'Pravila jos nisu dodana.', en: 'Rules have not been added yet.' },
    'rulesNotAddedDesc': { hr: 'Admin ih moze dodati i urediti unutar admin panela.', en: 'Admin can add and edit them in the admin panel.' },
    'note': { hr: 'Napomena', en: 'Note' },
    'footerDesc': { hr: 'Pravila i informacije za sve clanove zajednice.', en: 'Rules and information for all community members.' },

    // Statistika
    'serverStats': { hr: 'Statistika Servera', en: 'Server Statistics' },
    'serverStatsDesc': { hr: 'Pregled stanja servera, igrača i ukupne statistike farmi.', en: 'Overview of server status, players, and total farm statistics.' },
    'serverStatus': { hr: 'Status Servera', en: 'Server Status' },
    'serverOnline': { hr: 'Server Online', en: 'Server Online' },
    'serverOffline': { hr: 'Server Offline', en: 'Server Offline' },
    'playersOnline': { hr: 'Igrači Online', en: 'Players Online' },
    'discordMembers': { hr: 'Discord Članovi', en: 'Discord Members' },
    'totalFarms': { hr: 'Ukupno Farmi', en: 'Total Farms' },
    'totalFields': { hr: 'Ukupno Polja', en: 'Total Fields' },
    'totalVehicles': { hr: 'Ukupno Vozila', en: 'Total Vehicles' },
    'map': { hr: 'Mapa', en: 'Map' },
    'mods': { hr: 'Modovi', en: 'Mods' },
    'currentlyPlaying': { hr: '🟢 Trenutno igraju', en: '🟢 Currently Playing' },
    'serverOverview': { hr: '📊 Pregled servera', en: '📊 Server Overview' },
    'activeFarmsLabel': { hr: 'Aktivne Farme', en: 'Active Farms' },
    'registeredPlayers': { hr: 'Registrirani Igrači', en: 'Registered Players' },
    'worldStats': { hr: '🌍 Statistika svijeta', en: '🌍 World Statistics' },
    'totalAreaLabel': { hr: 'Ukupna Površina', en: 'Total Area' },
    'totalSilos': { hr: 'Skladišta', en: 'Storages' },
    'totalProductions': { hr: 'Proizvodnje', en: 'Productions' },
    'totalAnimals': { hr: 'Životinja', en: 'Animals' },

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

    // No-permission page
    'accessDenied': { hr: '🚫 Pristup odbijen', en: '🚫 Access Denied' },
    'noRoleAccess': { hr: 'Nemaš potrebnu rolu za pristup ovoj stranici.', en: 'You don\'t have the required role to access this page.' },
    'checkRoles': { hr: 'Ako smatraš da je ovo greška, provjeri svoje role na Discord serveru.', en: 'If you think this is a mistake, check your roles on the Discord server.' },
    'backToHome': { hr: 'Povratak na početnu', en: 'Back to Home' },

    // Profile
    'adminBadge': { hr: '👑 Admin', en: '👑 Admin' },
    'playerBadge': { hr: '🚜 Player', en: '🚜 Player' },

    // Gallery comments
    'delete': { hr: 'Obriši', en: 'Delete' },
    'commentsCount': { hr: 'komentara', en: 'comments' },
    'commentsHeader': { hr: 'Komentari', en: 'Comments' },
    'noComments': { hr: 'Još nema komentara.', en: 'No comments yet.' },
    'addCommentPlaceholder': { hr: 'Dodaj komentar...', en: 'Add a comment...' },
    'publish': { hr: 'Objavi', en: 'Post' },
    'allComments': { hr: 'Svi komentari', en: 'All comments' },
    'noCommentsForImage': { hr: 'Još nema komentara za ovu sliku.', en: 'No comments for this image yet.' },
    'addComment': { hr: 'Dodaj komentar', en: 'Add a comment' },
    'writeCommentPlaceholder': { hr: 'Napiši komentar...', en: 'Write a comment...' },
    'publishComment': { hr: 'Objavi komentar', en: 'Post comment' },
    'noUploadedImages': { hr: 'Nema uploadanih slika.', en: 'No uploaded images.' },
    'close': { hr: 'Zatvori', en: 'Close' },
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

    // Insert controls inside the navbar <ul> as last items
    var ul = navbar.querySelector('ul');
    if (!ul) return;

    var li = document.createElement('li');
    li.className = 'site-controls';
    li.innerHTML =
      '<button class="lang-flag" data-lang="hr" title="Hrvatski" onclick="window.__setLang(\'hr\')">' +
        '<img src="/images/flag-hr.svg" alt="HR" width="22" height="15">' +
      '</button>' +
      '<button class="lang-flag" data-lang="en" title="English" onclick="window.__setLang(\'en\')">' +
        '<img src="/images/flag-us.svg" alt="EN" width="22" height="15">' +
      '</button>' +
      '<span class="site-controls-divider"></span>' +
      '<button class="theme-btn" data-theme="green" title="Zelena tema" onclick="window.__setTheme(\'green\')"><span style="background:#00ff7a"></span></button>' +
      '<button class="theme-btn" data-theme="gold" title="Zlatna tema" onclick="window.__setTheme(\'gold\')"><span style="background:#ffd700"></span></button>';

    ul.appendChild(li);
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
