// ui.js - Initialises and controls UI components + shared helpers

// ========== Shared Helper Functions (added for all pages) ==========
function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/[&<>"']/g, function(c) {
    if (c === '&') return '&amp;';
    if (c === '<') return '&lt;';
    if (c === '>') return '&gt;';
    if (c === '"') return '&quot;';
    return '&#39;';
  });
}

function initHeader() {
  const header = document.querySelector(".site-header");
  if (!header) return;
  const onScroll = () => {
    if (window.scrollY > 30) header.classList.add("scrolled");
    else header.classList.remove("scrolled");
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
  const toggle = header.querySelector(".nav-toggle");
  const nav = header.querySelector(".nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => nav.classList.toggle("open"));
    nav.addEventListener("click", (e) => {
      if (e.target.tagName === "A") nav.classList.remove("open");
    });
  }
}

// ========== Original UI code (unchanged) ==========
(function() {
  // Helper: data-state toggling (not used elsewhere, kept for reference)
  function toggleAttribute(element, attr, value) {
    if (element.hasAttribute(attr)) {
      element.removeAttribute(attr);
    } else {
      element.setAttribute(attr, value);
    }
  }

  // --- Tabs ---
  document.querySelectorAll('[data-ui="tabs"]').forEach(tabsContainer => {
    const triggers = tabsContainer.querySelectorAll('[data-ui="tabs-trigger"]');
    const panels = tabsContainer.querySelectorAll('[data-ui="tabs-panel"]');
    if (!triggers.length) return;
    const activate = (index) => {
      triggers.forEach((t, i) => {
        if (i === index) t.classList.add('active');
        else t.classList.remove('active');
      });
      panels.forEach((p, i) => {
        if (i === index) p.classList.add('active');
        else p.classList.remove('active');
      });
    };
    triggers.forEach((trigger, idx) => {
      trigger.addEventListener('click', () => activate(idx));
    });
    // activate first by default
    activate(0);
  });

  // --- Accordion ---
  document.querySelectorAll('[data-ui="accordion"]').forEach(accordion => {
    accordion.querySelectorAll('[data-ui="accordion-item"]').forEach(item => {
      const trigger = item.querySelector('[data-ui="accordion-trigger"]');
      if (!trigger) return;
      trigger.addEventListener('click', () => {
        const open = item.classList.contains('open');
        // close all siblings if not multi?
        const multi = accordion.getAttribute('data-multi') === 'true';
        if (!multi) {
          accordion.querySelectorAll('[data-ui="accordion-item"]').forEach(i => {
            i.classList.remove('open');
          });
        }
        if (!open) item.classList.add('open');
        else item.classList.remove('open');
      });
    });
  });

  // --- Dropdowns ---
  document.querySelectorAll('[data-ui="dropdown"]').forEach(dropdown => {
    const trigger = dropdown.querySelector('[data-ui="dropdown-trigger"]');
    const menu = dropdown.querySelector('[data-ui="dropdown-menu"]');
    if (!trigger || !menu) return;
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = menu.classList.contains('open');
      // close all other dropdowns
      document.querySelectorAll('[data-ui="dropdown-menu"]').forEach(m => m.classList.remove('open'));
      if (!isOpen) menu.classList.add('open');
    });
    // close when clicking outside
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target)) {
        menu.classList.remove('open');
      }
    });
  });

  // --- Modal / Dialog ---
  const modalStack = [];
  window.openModal = (modalId) => {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    modalStack.push(modal);
  };
  window.closeModal = (modalId) => {
    const modal = modalId ? document.getElementById(modalId) : modalStack.pop();
    if (modal) {
      modal.classList.remove('open');
      document.body.style.overflow = '';
    }
  };
  // close on overlay click and escape key
  document.addEventListener('click', (e) => {
    if (e.target.classList && e.target.classList.contains('modal-overlay')) {
      closeModal(e.target.id);
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modalStack.length) {
      closeModal();
    }
  });

  // --- Alert Dialog ---
  window.alertDialog = (options) => {
    const { title, description, confirmText = 'OK', cancelText = 'Cancel', onConfirm, onCancel } = options;
    const id = 'dynamic-alert-dialog';
    let existing = document.getElementById(id);
    if (existing) existing.remove();
    const dialogHtml = `
      <div id="${id}" class="modal-overlay" style="display:flex;">
        <div class="modal-container" style="max-width: 400px;">
          <div class="modal-header">
            <span class="modal-title">${escapeHtml(title)}</span>
            <button class="modal-close" onclick="closeModal('${id}')">&times;</button>
          </div>
          <div class="modal-body">
            ${escapeHtml(description)}
          </div>
          <div class="modal-footer">
            <button class="btn btn-outline" onclick="closeModal('${id}'); if(${onCancel}) onCancel();">${cancelText}</button>
            <button class="btn btn-primary" onclick="closeModal('${id}'); if(${onConfirm}) onConfirm();">${confirmText}</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', dialogHtml);
    openModal(id);
  };

  // --- Toasts ---
  let toastContainer = document.querySelector('.toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }
  window.showToast = (message, type = 'info', duration = 3000) => {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerText = message;
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, duration);
  };

  // --- Tooltips (auto) ---
  document.querySelectorAll('[data-tooltip]').forEach(el => {
    const tooltipText = el.getAttribute('data-tooltip');
    if (!el.querySelector('.tooltip-text')) {
      const tooltipSpan = document.createElement('span');
      tooltipSpan.className = 'tooltip-text';
      tooltipSpan.innerText = tooltipText;
      el.classList.add('tooltip');
      el.appendChild(tooltipSpan);
    }
  });

  // --- Switch toggle value retrieval (optional) ---
  document.querySelectorAll('.switch input').forEach(switchInput => {
    switchInput.addEventListener('change', (e) => {
      const hiddenInput = switchInput.closest('.switch')?.querySelector('input[type="hidden"]');
      if (hiddenInput) hiddenInput.value = e.target.checked ? 'on' : 'off';
    });
  });

  // --- Progress bar updates ---
  window.updateProgress = (element, percent) => {
    const bar = element.querySelector('.progress-bar');
    if (bar) bar.style.width = Math.min(100, Math.max(0, percent)) + '%';
  };
})();

// ========== Auto‑initialise header on all pages ==========
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initHeader);
} else {
  initHeader();
}