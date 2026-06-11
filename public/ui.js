// ui.js - Centralised helper functions and UI components
// Now ensures window.openModal and window.closeModal are defined.

// ========== SHARED HELPERS ==========
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

function safeUrl(url, fallback = "") {
  if (!url) return fallback;
  try {
    const u = new URL(url, window.location.origin);
    if (["http:", "https:"].includes(u.protocol)) return u.href;
  } catch(e) {}
  return fallback;
}

function sanitizeHtml(html) {
  const tpl = document.createElement("template");
  tpl.innerHTML = String(html);
  const allowedTags = new Set(["P","BR","STRONG","EM","B","I","U","UL","OL","LI","H1","H2","H3","H4","H5","H6","BLOCKQUOTE","A","IMG","HR","SPAN","DIV","FIGURE","FIGCAPTION","PRE","CODE"]);
  const allowedAttrs = { A: ["href","title","target","rel"], IMG: ["src","alt","title"] };
  const walk = (node) => {
    [...node.childNodes].forEach(child => {
      if (child.nodeType === 1) {
        if (!allowedTags.has(child.tagName)) {
          child.replaceWith(...child.childNodes);
          return;
        }
        const allowed = allowedAttrs[child.tagName] || [];
        [...child.attributes].forEach(a => {
          if (!allowed.includes(a.name)) child.removeAttribute(a.name);
          if (a.name === "href" || a.name === "src") {
            const v = safeUrl(a.value);
            if (!v) child.removeAttribute(a.name);
            else child.setAttribute(a.name, v);
          }
        });
        if (child.tagName === "A") {
          child.setAttribute("rel","noopener noreferrer");
          child.setAttribute("target","_blank");
        }
        walk(child);
      } else if (child.nodeType === 8) child.remove();
    });
  };
  walk(tpl.content);
  return tpl.innerHTML;
}

function fmtPrice(v) {
  if (v == null || isNaN(Number(v))) return "-";
  return "KSh " + Number(v).toLocaleString();
}

function fmtDate(d) {
  if (!d) return "-";
  try {
    return new Date(d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  } catch(e) { return d; }
}

function truncate(str, n = 120) {
  const s = String(str).replace(/<[^>]*>/g, "");
  return s.length > n ? s.slice(0, n).trim() + "..." : s;
}

function renderStars(rating) {
  const full = Math.floor(rating);
  const empty = 5 - full;
  return '<span class="stars">' + '\u2605'.repeat(full) + '\u2606'.repeat(empty) + '</span>';
}

function isValidEmail(email) {
  return /^\S+@\S+\.\S+$/.test(String(email || "").trim());
}

function showAlert(element, msg, kind = "error") {
  if (!element) return;
  element.innerHTML = `<div class="alert ${kind}">${escapeHtml(msg)}</div>`;
  if (kind === "success") setTimeout(() => { element.innerHTML = ""; }, 6000);
}

// Simple toast that does not recursively call itself
function showToast(message, type = "info") {
  const existing = document.querySelector('.custom-toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `custom-toast ${type}`;
  toast.innerText = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ========== CSRF TOKEN HELPERS ==========
function getCsrfToken() {
  const match = document.cookie.match(new RegExp('(^| )csrf_token=([^;]+)'));
  return match ? match[2] : null;
}

// ========== UNIFIED API REQUEST (CSRF only for state-changing methods) ==========
async function apiRequest(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  const method = (options.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: { ...headers, ...options.headers },
    credentials: 'include'
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Request failed');
  return data;
}

// ========== MODAL HELPERS ==========
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }
}

// Make them global
window.openModal = openModal;
window.closeModal = closeModal;
window.showToast = showToast;

// ========== UI INITIALISATION ==========
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

// ========== ORIGINAL UI COMPONENTS (accordion, tabs, etc.) ==========
(function() {
  // Tabs
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
    activate(0);
  });

  // Accordion
  document.querySelectorAll('[data-ui="accordion"]').forEach(accordion => {
    accordion.querySelectorAll('[data-ui="accordion-item"]').forEach(item => {
      const trigger = item.querySelector('[data-ui="accordion-trigger"]');
      if (!trigger) return;
      trigger.addEventListener('click', () => {
        const open = item.classList.contains('open');
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

  // Dropdowns
  document.querySelectorAll('[data-ui="dropdown"]').forEach(dropdown => {
    const trigger = dropdown.querySelector('[data-ui="dropdown-trigger"]');
    const menu = dropdown.querySelector('[data-ui="dropdown-menu"]');
    if (!trigger || !menu) return;
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = menu.classList.contains('open');
      document.querySelectorAll('[data-ui="dropdown-menu"]').forEach(m => m.classList.remove('open'));
      if (!isOpen) menu.classList.add('open');
    });
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target)) menu.classList.remove('open');
    });
  });

  // Tooltips
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

  // Progress bar
  window.updateProgress = (element, percent) => {
    const bar = element.querySelector('.progress-bar');
    if (bar) bar.style.width = Math.min(100, Math.max(0, percent)) + '%';
  };
})();

// Auto-init header and set current year in footer
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initHeader();
    const yearSpan = document.getElementById('year');
    if (yearSpan) yearSpan.textContent = new Date().getFullYear();
  });
} else {
  initHeader();
  const yearSpan = document.getElementById('year');
  if (yearSpan) yearSpan.textContent = new Date().getFullYear();
}
