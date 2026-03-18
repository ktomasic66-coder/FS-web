(function () {
  'use strict';

  var translations = {
    home: { hr: 'Početna' },
    gallery: { hr: 'Galerija' },
    rules: { hr: 'Pravila' },
    statistics: { hr: 'Statistika' },
    myFarm: { hr: 'Moja farma' },
    profile: { hr: 'Profil' },
    admin: { hr: 'Admin' },
    bot: { hr: 'Bot' },
    logout: { hr: 'Odjava' },
    login: { hr: 'Prijava' },

    heroTitle: { hr: 'Slavonska Ravnica | FS25 server' },
    heroDesc: { hr: 'Realističan Farming Simulator 25 multiplayer s fokusom na ekonomiju, timski rad i dugoročni razvoj farmi.' },
    loginDiscord: { hr: 'Prijava putem Discorda' },
    noPosts: { hr: 'Nema objava.' },

    whoAreWe: { hr: 'Tko smo mi' },
    whoAreWeDesc: { hr: 'Slavonska Ravnica je zajednica igrača koji žele kvalitetno i organizirano FS25 iskustvo. Gradimo server gdje trud ima vrijednost, a napredak dolazi kroz rad i suradnju. Kod nas farme imaju priču.' },
    realisticEcon: { hr: 'Realistična ekonomija' },
    realisticEconDesc: { hr: 'Uravnotežen sustav napretka bez preskakanja faza.' },
    activeCommunity: { hr: 'Aktivna zajednica' },
    activeCommunityDesc: { hr: 'Ozbiljna i organizirana ekipa.' },
    events: { hr: 'Događaji' },
    eventsDesc: { hr: 'Redoviti izazovi i zajednički projekti.' },
    stableServer: { hr: 'Stabilan server' },
    stableServerDesc: { hr: 'Optimizirano i dugoročno iskustvo.' },
    howToJoin: { hr: 'Kako se pridružiti' },
    step1: { hr: 'Prijavi se putem Discorda' },
    step2: { hr: 'Pridruži se Discordu' },
    step3: { hr: 'Otvori tiket za PLAYER rolu' },
    step4: { hr: 'Kreni graditi svoju farmu' },
    readyForMultiplayer: { hr: 'Spreman za ozbiljan multiplayer?' },
    loginToJoin: { hr: 'Prijavi se kako bi se pridružio' },
    joinCommunity: { hr: 'Pridruži se zajednici' },

    activeFarms: { hr: 'Aktivne farme' },
    balance: { hr: 'Stanje' },
    area: { hr: 'Površina' },
    noPlayersOnFarm: { hr: 'Nema igrača na farmi' },
    news: { hr: 'Novosti' },

    farmManagement: { hr: 'Upravljanje farmom' },
    accountBalance: { hr: 'Stanje računa' },
    sendMoney: { hr: 'Pošalji novac' },
    targetFarm: { hr: 'Ciljna farma' },
    selectFarm: { hr: '-- Odaberi farmu --' },
    amount: { hr: 'Iznos (€)' },
    queueTransfer: { hr: 'Zakaži' },
    transferNote: { hr: '* Izvršava se nakon sljedećeg spremanja igre' },
    vehicles: { hr: 'Vozila' },
    fields: { hr: 'Polja' },
    animals: { hr: 'Životinje' },
    production: { hr: 'Proizvodnja' },
    storage: { hr: 'Skladišta' },
    players: { hr: 'Igrači' },
    noVehicles: { hr: 'Nema vozila' },
    noFields: { hr: 'Nema polja' },
    noAnimals: { hr: 'Nema životinja' },
    noProduction: { hr: 'Nema proizvodnje' },
    emptyStorage: { hr: 'Skladište je prazno' },

    communityMedia: { hr: 'Mediji zajednice' },
    galleryTitle: { hr: 'Galerija zajednice' },
    gallerySubtitle: { hr: 'Podijeli trenutke sa servera, reagiraj na objave i pregledaj komentare u proširenom prikazu.' },
    chooseImage: { hr: 'Odaberi sliku' },
    imageDesc: { hr: 'Opis slike' },
    publishImage: { hr: 'Objavi sliku' },

    myProfile: { hr: 'Moj profil' },
    noExtraRoles: { hr: 'Nema dodatnih rola' },

    serverPolicy: { hr: 'Pravila servera' },
    rulesNotAdded: { hr: 'Pravila još nisu dodana.' },
    rulesNotAddedDesc: { hr: 'Admin ih može dodati i urediti unutar admin panela.' },
    note: { hr: 'Napomena' },
    footerDesc: { hr: 'Pravila i informacije za sve članove zajednice.' },

    serverStats: { hr: 'Statistika servera' },
    serverStatsDesc: { hr: 'Pregled stanja servera, igrača i ukupne statistike farmi.' },
    serverStatus: { hr: 'Status servera' },
    serverOnline: { hr: 'Server je online' },
    serverOffline: { hr: 'Server je offline' },
    playersOnline: { hr: 'Igrači online' },
    discordMembers: { hr: 'Discord članovi' },
    totalFarms: { hr: 'Ukupno farmi' },
    totalFields: { hr: 'Ukupno polja' },
    totalVehicles: { hr: 'Ukupno vozila' },
    map: { hr: 'Mapa' },
    mods: { hr: 'Modovi' },
    currentlyPlaying: { hr: 'Trenutačno igraju' },
    serverOverview: { hr: 'Pregled servera' },
    activeFarmsLabel: { hr: 'Aktivne farme' },
    registeredPlayers: { hr: 'Registrirani igrači' },
    worldStats: { hr: 'Statistika svijeta' },
    totalAreaLabel: { hr: 'Ukupna površina' },
    totalSilos: { hr: 'Skladišta' },
    totalProductions: { hr: 'Proizvodnje' },
    totalAnimals: { hr: 'Životinje' },

    all: { hr: 'Sve' },
    lowFuel: { hr: 'Malo goriva' },
    damaged: { hr: 'Oštećeno' },
    dirty: { hr: 'Prljavo' },
    needsAction: { hr: 'Potrebna radnja' },
    planted: { hr: 'Zasađeno' },
    empty: { hr: 'Prazno' },
    lowHealth: { hr: 'Slabo zdravlje' },
    owned: { hr: 'Kupljeno' },
    notOwned: { hr: 'Nije kupljeno' },
    full: { hr: 'Puno (>80%)' },
    low: { hr: 'Prazno (<20%)' },
    searchVehicles: { hr: 'Pretraži vozila...' },
    searchFields: { hr: 'Pretraži polja...' },
    searchAnimals: { hr: 'Pretraži životinje...' },
    searchProduction: { hr: 'Pretraži proizvodnju...' },
    searchStorage: { hr: 'Pretraži skladišta...' },
    noResults: { hr: 'Nema rezultata za odabrani filtar.' },

    fuel: { hr: 'Gorivo' },
    condition: { hr: 'Stanje' },
    dirtiness: { hr: 'Prljavština' },
    health: { hr: 'Zdravlje' },
    productivity: { hr: 'Produktivnost' },
    reproduction: { hr: 'Reprodukcija' },
    food: { hr: 'Hrana' },
    products: { hr: 'Proizvodi' },
    inputs: { hr: 'Ulazi' },
    outputs: { hr: 'Izlazi' },
    total: { hr: 'Ukupno' },
    contents: { hr: 'Sadržaj' },
    status: { hr: 'Status' },
    ownership: { hr: 'Vlasništvo' },
    yes: { hr: 'Da' },
    no: { hr: 'Ne' },
    online: { hr: 'Online' },
    offline: { hr: 'Offline' },
    played: { hr: 'odigrano' },
    culture: { hr: 'Kultura' },
    surfaceArea: { hr: 'Površina' },
    growth: { hr: 'Rast' },
    plowing: { hr: 'Oranje' },
    lime: { hr: 'Vapno' },
    fertilizer: { hr: 'Gnojivo' },
    weeds: { hr: 'Korovi' },
    rolling: { hr: 'Valjanje' },
    price: { hr: 'Cijena' },
    notBought: { hr: 'Nije kupljeno' },
    fills: { hr: 'Punjenja' },

    noFarmYet: { hr: 'Još nemaš kreiranu farmu' },
    contactAdmin: { hr: 'Javi se adminu ili kreiraj farmu putem Discord bota kako bi započeo svoje poljoprivredno carstvo.' },
    joinDiscord: { hr: 'Pridruži se Discordu' },
    loginForFarm: { hr: 'Prijavi se za pristup svojoj farmi' },
    loginRequired: { hr: 'Za pregled tvoje farme potrebna je prijava putem Discord računa.' },
    loginBtn: { hr: 'Prijava putem Discorda' },

    accessDenied: { hr: 'Pristup odbijen' },
    noRoleAccess: { hr: 'Nemaš potrebnu rolu za pristup ovoj stranici.' },
    checkRoles: { hr: 'Ako smatraš da je ovo greška, provjeri svoje role na Discord serveru.' },
    backToHome: { hr: 'Povratak na početnu' },

    adminBadge: { hr: 'Admin' },
    playerBadge: { hr: 'Igrač' },

    delete: { hr: 'Obriši' },
    commentsCount: { hr: 'komentara' },
    commentsHeader: { hr: 'Komentari' },
    noComments: { hr: 'Još nema komentara.' },
    addCommentPlaceholder: { hr: 'Dodaj komentar...' },
    publish: { hr: 'Objavi' },
    allComments: { hr: 'Svi komentari' },
    noCommentsForImage: { hr: 'Još nema komentara za ovu sliku.' },
    addComment: { hr: 'Dodaj komentar' },
    writeCommentPlaceholder: { hr: 'Napiši komentar...' },
    publishComment: { hr: 'Objavi komentar' },
    noUploadedImages: { hr: 'Nema učitanih slika.' },
    close: { hr: 'Zatvori' }
  };

  var currentLang = 'hr';
  var currentTheme = localStorage.getItem('sr-theme') || 'green';

  function setLanguage() {
    currentLang = 'hr';
    applyTranslations();
    updateFlagButtons();
  }

  function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      if (!translations[key] || !translations[key][currentLang]) return;

      if (el.tagName === 'INPUT' && el.type !== 'submit') {
        el.placeholder = translations[key][currentLang];
        return;
      }

      if (el.tagName === 'OPTION') {
        el.textContent = translations[key][currentLang];
        return;
      }

      el.textContent = translations[key][currentLang];
    });
  }

  function updateFlagButtons() {
    document.querySelectorAll('.lang-flag').forEach(function (flag) {
      flag.classList.toggle('active', flag.getAttribute('data-lang') === 'hr');
    });
  }

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
    document.querySelectorAll('.theme-btn').forEach(function (button) {
      button.classList.toggle('active', button.getAttribute('data-theme') === currentTheme);
    });
  }

  function injectControls() {
    var navbar = document.querySelector('.navbar');
    if (!navbar) return;

    var ul = navbar.querySelector('ul');
    if (!ul) return;

    var li = document.createElement('li');
    li.className = 'site-controls';
    li.innerHTML =
      '<button class="lang-flag active" data-lang="hr" title="Hrvatski" onclick="window.__setLang(\'hr\')">' +
        '<img src="/images/flag-hr.svg" alt="HR" width="22" height="15">' +
      '</button>' +
      '<span class="site-controls-divider"></span>' +
      '<button class="theme-btn" data-theme="green" title="Zelena tema" onclick="window.__setTheme(\'green\')"><span style="background:#00ff7a"></span></button>' +
      '<button class="theme-btn" data-theme="gold" title="Zlatna tema" onclick="window.__setTheme(\'gold\')"><span style="background:#ffd700"></span></button>';

    ul.appendChild(li);
  }

  window.__setLang = setLanguage;
  window.__setTheme = setTheme;

  document.addEventListener('DOMContentLoaded', function () {
    injectControls();
    applyTheme();
    applyTranslations();
    updateFlagButtons();
    updateThemeButtons();
  });
})();
