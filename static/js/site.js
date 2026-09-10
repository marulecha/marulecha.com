/* marulecha.com — shared site behaviour
   - FX toggle (persists to localStorage 'animationsDisabled', live, no reload)
   - mobile navigation
   - active nav link
   - toast notifications (window.toast)
   - scroll reveal
   - global "/" shortcut to focus a search field when the page has one
*/
(function () {
  'use strict';

  var html = document.documentElement;
  var STORAGE_KEY = 'animationsDisabled';
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function fxDisabled() {
    try { return localStorage.getItem(STORAGE_KEY) === 'true' || reduceMotion; } catch (e) { return reduceMotion; }
  }

  var listeners = [];
  function applyFx() {
    var off = fxDisabled();
    html.classList.toggle('no-fx', off);
    listeners.forEach(function (fn) { try { fn(!off); } catch (e) { /* noop */ } });
  }

  window.SiteFX = {
    enabled: function () { return !fxDisabled(); },
    onChange: function (fn) { listeners.push(fn); }
  };

  applyFx();

  document.addEventListener('DOMContentLoaded', function () {
    /* FX toggle */
    var sw = document.getElementById('fx-switch');
    if (sw) {
      sw.checked = !fxDisabled();
      if (reduceMotion) {
        sw.disabled = true;
        sw.closest('.fx-toggle').title = 'Animations are disabled by your system preference';
      }
      sw.addEventListener('change', function () {
        try {
          if (sw.checked) localStorage.removeItem(STORAGE_KEY);
          else localStorage.setItem(STORAGE_KEY, 'true');
        } catch (e) { /* storage blocked */ }
        applyFx();
        toast(sw.checked ? 'Effects enabled' : 'Effects disabled');
      });
    }

    /* Mobile nav */
    var navBtn = document.querySelector('.nav-toggle');
    var nav = document.getElementById('site-nav');
    if (navBtn && nav) {
      navBtn.addEventListener('click', function () {
        var open = nav.classList.toggle('is-open');
        html.classList.toggle('nav-open', open);
        navBtn.setAttribute('aria-expanded', String(open));
        navBtn.querySelector('.i-menu').hidden = open;
        navBtn.querySelector('.i-close').hidden = !open;
      });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && nav.classList.contains('is-open')) navBtn.click();
      });
      // leaving the phone breakpoint with the sheet open: reset state
      window.addEventListener('resize', function () {
        if (window.innerWidth > 860 && nav.classList.contains('is-open')) navBtn.click();
      });
    }

    /* Active nav link */
    if (nav) {
      var here = location.pathname.replace(/\/index\.html$/, '/').replace(/\/$/, '/index.html');
      Array.prototype.forEach.call(nav.querySelectorAll('a[href]'), function (a) {
        var target = new URL(a.getAttribute('href'), location.href).pathname.replace(/\/index\.html$/, '/').replace(/\/$/, '/index.html');
        if (target === here) a.setAttribute('aria-current', 'page');
      });
    }

    /* Scroll reveal */
    var revealables = document.querySelectorAll('[data-reveal]');
    if (revealables.length) {
      if ('IntersectionObserver' in window && !reduceMotion) {
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (en) {
            if (en.isIntersecting) { en.target.classList.add('is-in'); io.unobserve(en.target); }
          });
        }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 });
        revealables.forEach(function (el) { io.observe(el); });
        // Safety net: never leave content hidden if the observer is slow or never fires.
        setTimeout(function () { revealables.forEach(function (el) { el.classList.add('is-in'); }); }, 1500);
      } else {
        revealables.forEach(function (el) { el.classList.add('is-in'); });
      }
    }

    /* "/" focuses the first search input on the page */
    var search = document.querySelector('input[type="search"]');
    if (search) {
      if (search.dataset.placeholderShort && window.matchMedia('(max-width: 700px)').matches) {
        search.placeholder = search.dataset.placeholderShort;
      }
      document.addEventListener('keydown', function (e) {
        var tag = (e.target.tagName || '').toLowerCase();
        var typing = tag === 'input' || tag === 'textarea' || e.target.isContentEditable;
        if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
          e.preventDefault();
          search.focus();
          search.select();
        }
        if (e.key === 'Escape' && e.target === search) {
          search.value = '';
          search.dispatchEvent(new Event('input', { bubbles: true }));
          search.blur();
        }
      });
    }

    /* Footer year */
    var y = document.getElementById('year');
    if (y) y.textContent = String(new Date().getFullYear());
  });

  /* Toast */
  var host;
  function toast(message, ms) {
    if (!host) {
      host = document.createElement('div');
      host.className = 'toast-host';
      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      document.body.appendChild(host);
    }
    var el = document.createElement('div');
    el.className = 'toast';
    el.textContent = message;
    host.appendChild(el);
    setTimeout(function () {
      el.classList.add('is-leaving');
      setTimeout(function () { el.remove(); }, 300);
    }, ms || 2200);
  }
  window.toast = toast;

  /* Clipboard helper with fallback */
  window.copyText = function (text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy') ? resolve() : reject(new Error('copy failed')); }
      catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  };
})();
