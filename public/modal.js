(function () {
  const modalRoot = document.createElement('div');
  modalRoot.className = 'fs-modal-overlay';
  modalRoot.innerHTML = [
    '<div class="fs-modal" role="dialog" aria-modal="true" aria-labelledby="fs-modal-title">',
    '  <div class="fs-modal-header">',
    '    <p class="fs-modal-kicker">Potvrda</p>',
    '    <h2 id="fs-modal-title" class="fs-modal-title"></h2>',
    '  </div>',
    '  <p class="fs-modal-message"></p>',
    '  <div class="fs-modal-input-wrap" hidden>',
    '    <input class="fs-modal-input" type="text" />',
    '  </div>',
    '  <div class="fs-modal-actions">',
    '    <button type="button" class="fs-modal-btn fs-modal-cancel">Odustani</button>',
    '    <button type="button" class="fs-modal-btn fs-modal-confirm">Potvrdi</button>',
    '  </div>',
    '</div>',
  ].join('');

  document.addEventListener('DOMContentLoaded', function () {
    document.body.appendChild(modalRoot);
  });

  const titleEl = () => modalRoot.querySelector('.fs-modal-title');
  const messageEl = () => modalRoot.querySelector('.fs-modal-message');
  const inputWrapEl = () => modalRoot.querySelector('.fs-modal-input-wrap');
  const inputEl = () => modalRoot.querySelector('.fs-modal-input');
  const confirmBtn = () => modalRoot.querySelector('.fs-modal-confirm');
  const cancelBtn = () => modalRoot.querySelector('.fs-modal-cancel');

  function closeModal() {
    modalRoot.classList.remove('is-open');
    document.body.classList.remove('modal-open');
    inputWrapEl().hidden = true;
    inputEl().value = '';
  }

  function openModal(options) {
    titleEl().textContent = options.title || 'Potvrda';
    messageEl().textContent = options.message || '';
    confirmBtn().textContent = options.confirmLabel || 'Potvrdi';
    cancelBtn().textContent = options.cancelLabel || 'Odustani';
    cancelBtn().style.display = options.showCancel === false ? 'none' : 'inline-flex';

    if (options.mode === 'prompt') {
      inputWrapEl().hidden = false;
      inputEl().value = options.defaultValue || '';
      setTimeout(function () {
        inputEl().focus();
        inputEl().select();
      }, 10);
    } else {
      inputWrapEl().hidden = true;
      setTimeout(function () {
        confirmBtn().focus();
      }, 10);
    }

    modalRoot.classList.add('is-open');
    document.body.classList.add('modal-open');

    return new Promise(function (resolve) {
      function cleanup() {
        confirmBtn().removeEventListener('click', onConfirm);
        cancelBtn().removeEventListener('click', onCancel);
        modalRoot.removeEventListener('click', onBackdrop);
        document.removeEventListener('keydown', onKeydown);
      }

      function finish(result) {
        cleanup();
        closeModal();
        resolve(result);
      }

      function onConfirm() {
        if (options.mode === 'prompt') {
          finish(inputEl().value);
          return;
        }
        finish(true);
      }

      function onCancel() {
        finish(options.mode === 'prompt' ? null : false);
      }

      function onBackdrop(event) {
        if (event.target === modalRoot) {
          onCancel();
        }
      }

      function onKeydown(event) {
        if (!modalRoot.classList.contains('is-open')) return;
        if (event.key === 'Escape') onCancel();
        if (event.key === 'Enter' && options.mode !== 'prompt') onConfirm();
      }

      confirmBtn().addEventListener('click', onConfirm);
      cancelBtn().addEventListener('click', onCancel);
      modalRoot.addEventListener('click', onBackdrop);
      document.addEventListener('keydown', onKeydown);
    });
  }

  window.fsConfirm = function (message, options) {
    return openModal({
      title: (options && options.title) || 'Potvrdi akciju',
      message: message,
      confirmLabel: (options && options.confirmLabel) || 'Potvrdi',
      cancelLabel: (options && options.cancelLabel) || 'Odustani',
    });
  };

  window.fsAlert = function (message, options) {
    return openModal({
      title: (options && options.title) || 'Obavijest',
      message: message,
      confirmLabel: (options && options.confirmLabel) || 'U redu',
      showCancel: false,
    });
  };

  window.fsPrompt = function (message, defaultValue, options) {
    return openModal({
      title: (options && options.title) || 'Unos',
      message: message,
      confirmLabel: (options && options.confirmLabel) || 'Spremi',
      cancelLabel: (options && options.cancelLabel) || 'Odustani',
      mode: 'prompt',
      defaultValue: defaultValue || '',
    });
  };

  document.addEventListener('submit', function (event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const confirmMessage = form.getAttribute('data-confirm');
    if (!confirmMessage || form.dataset.confirmed === 'true') {
      form.dataset.confirmed = '';
      return;
    }

    event.preventDefault();
    window.fsConfirm(confirmMessage, {
      title: form.getAttribute('data-confirm-title') || 'Potvrdi akciju',
      confirmLabel: form.getAttribute('data-confirm-ok') || 'Potvrdi',
      cancelLabel: form.getAttribute('data-confirm-cancel') || 'Odustani',
    }).then(function (confirmed) {
      if (!confirmed) return;
      form.dataset.confirmed = 'true';
      form.requestSubmit();
    });
  });
})();
