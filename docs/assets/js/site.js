(function () {
  'use strict';

  var root = document.documentElement;

  // theme toggle -----------------------------------------------------------
  var toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      if (current !== 'light' && current !== 'dark') {
        current = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try {
        localStorage.setItem('theme', next);
      } catch (e) {}
    });
  }

  // mobile drawer ----------------------------------------------------------
  // the markup works without js through :target; here the same links become
  // a class toggle so focus and the scrim can be handled properly.
  var opener = document.getElementById('drawerOpen');
  var sidebar = document.getElementById('sidebar');
  var scrim = document.getElementById('drawerScrim');
  var closer = document.querySelector('.drawer-close');

  function getFocusable() {
    var nodes = sidebar.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])');
    return Array.prototype.filter.call(nodes, function (node) {
      return node.offsetWidth > 0 || node.offsetHeight > 0 || node.getClientRects().length > 0;
    });
  }

  function trapFocus(e) {
    if (e.key !== 'Tab') return;
    var focusable = getFocusable();
    if (!focusable.length) return;
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first || !sidebar.contains(document.activeElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last || !sidebar.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function openDrawer(event) {
    if (event) event.preventDefault();
    sidebar.classList.add('is-open');
    if (scrim) scrim.hidden = false;
    if (opener) opener.setAttribute('aria-expanded', 'true');
    var focusable = getFocusable();
    if (focusable.length) focusable[0].focus();
    document.addEventListener('keydown', trapFocus);
  }

  function closeDrawer(event) {
    if (event) event.preventDefault();
    if (!sidebar.classList.contains('is-open')) return;
    sidebar.classList.remove('is-open');
    if (scrim) scrim.hidden = true;
    document.removeEventListener('keydown', trapFocus);
    if (opener) {
      opener.setAttribute('aria-expanded', 'false');
      opener.focus();
    }
  }

  if (opener && sidebar) {
    var desktop = window.matchMedia('(min-width: 900px)');

    // the drawer is a mobile affordance; crossing into the desktop layout
    // leaves it open with a trap installed unless it is closed here.
    if (desktop.addEventListener) {
      desktop.addEventListener('change', function (e) {
        if (e.matches) closeDrawer();
      });
    } else if (desktop.addListener) {
      desktop.addListener(function (e) {
        if (e.matches) closeDrawer();
      });
    }

    // the css :target path can open the drawer without the class ever being
    // set, so no focus trap is installed; adopt that state on load and on
    // every fragment change.
    function syncTarget() {
      if (!desktop.matches && sidebar.matches(':target')) openDrawer();
    }
    window.addEventListener('hashchange', syncTarget);
    syncTarget();

    opener.addEventListener('click', openDrawer);
    if (closer) closer.addEventListener('click', closeDrawer);
    if (scrim) scrim.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeDrawer();
    });
    document.addEventListener('click', function (e) {
      if (!sidebar.classList.contains('is-open')) return;
      if (sidebar.contains(e.target) || opener.contains(e.target)) return;
      closeDrawer();
    });
  }

  // code panel chrome ------------------------------------------------------
  var panels = document.querySelectorAll('.prose .highlighter-rouge, .prose figure.highlight, .hero-panel .highlighter-rouge');
  Array.prototype.forEach.call(panels, function (panel) {
    var code = panel.querySelector('code');
    if (!code) return;

    var lang = '';
    var match = (panel.className || '').match(/language-([A-Za-z0-9_+-]+)/);
    if (match) {
      lang = match[1];
    } else if (code.getAttribute('data-lang')) {
      lang = code.getAttribute('data-lang');
    } else {
      var inner = (code.className || '').match(/language-([A-Za-z0-9_+-]+)/);
      if (inner) lang = inner[1];
    }
    if (lang === 'plaintext') lang = '';

    var chrome = document.createElement('div');
    chrome.className = 'code-chrome';

    var label = document.createElement('span');
    label.className = 'code-lang';
    label.textContent = lang || 'output';
    chrome.appendChild(label);

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'code-copy';
    button.textContent = 'Copy';
    button.addEventListener('click', function () {
      var text = code.textContent;
      var done = function () {
        button.textContent = 'Copied';
        window.setTimeout(function () { button.textContent = 'Copy'; }, 2000);
      };
      var failed = function () {
        button.textContent = 'Copy failed';
        window.setTimeout(function () { button.textContent = 'Copy'; }, 2000);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, failed);
      } else {
        failed();
      }
    });
    chrome.appendChild(button);

    panel.insertBefore(chrome, panel.firstChild);
  });

  // toc rail ---------------------------------------------------------------
  var rail = document.getElementById('rail');
  var article = document.getElementById('article');
  if (rail && article) {
    var headings = article.querySelectorAll('h2[id], h3[id]');
    if (headings.length > 1) {
      var title = document.createElement('p');
      title.className = 'rail-title';
      title.textContent = 'On this page';
      rail.appendChild(title);

      var list = document.createElement('ul');
      list.className = 'rail-list';
      var links = {};

      Array.prototype.forEach.call(headings, function (h) {
        var item = document.createElement('li');
        item.className = h.tagName === 'H3' ? 'rail-h3' : 'rail-h2';
        var link = document.createElement('a');
        link.href = '#' + h.id;
        link.textContent = h.textContent;
        item.appendChild(link);
        list.appendChild(item);
        links[h.id] = link;
      });
      rail.appendChild(list);

      if ('IntersectionObserver' in window) {
        var visible = {};
        var observer = new IntersectionObserver(function (entries) {
          entries.forEach(function (entry) {
            visible[entry.target.id] = entry.isIntersecting;
          });
          var currentId = null;
          Array.prototype.forEach.call(headings, function (h) {
            if (visible[h.id] && !currentId) currentId = h.id;
          });
          Object.keys(links).forEach(function (id) {
            links[id].classList.toggle('is-current', id === currentId);
          });
        }, { rootMargin: '0px 0px -70% 0px' });

        Array.prototype.forEach.call(headings, function (h) { observer.observe(h); });
      }
    }
  }
})();
