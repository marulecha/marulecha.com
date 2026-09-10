/* Home page: scripted terminal (reverse shell demo) + hero typewriter.
   Plain JS — replaces the previous React/Babel runtime. */
(function () {
  'use strict';

  var fxOn = function () { return !window.SiteFX || window.SiteFX.enabled(); };

  /* ------------------------------------------------------------------ */
  /* Hero typewriter                                                     */
  /* ------------------------------------------------------------------ */
  var tw = document.getElementById('typewriter');
  if (tw) {
    var PHRASES = [
      'Hello friend.',
      'Hello friend? That\'s lame..',
      'Break it. Understand it. Fix it.'
    ];
    var pi = 0, ci = 0, deleting = false, twTimer;

    function twStep() {
      if (!fxOn()) { tw.textContent = PHRASES[0]; twTimer = setTimeout(twStep, 800); return; }
      var phrase = PHRASES[pi];
      var delay;
      if (deleting) {
        ci--;
        tw.textContent = phrase.slice(0, ci);
        delay = 28;
        if (ci === 0) { deleting = false; pi = (pi + 1) % PHRASES.length; delay = 450; }
      } else {
        ci++;
        tw.textContent = phrase.slice(0, ci);
        delay = 55 + Math.random() * 60;
        if (phrase[ci - 1] === '?') delay = 900;
        if (ci === phrase.length) { deleting = true; delay = 2200; }
      }
      twTimer = setTimeout(twStep, delay);
    }
    setTimeout(twStep, 700);
  }

  /* ------------------------------------------------------------------ */
  /* Terminal                                                            */
  /* ------------------------------------------------------------------ */
  var root = document.getElementById('terminal');
  if (!root) return;

  var PROMPT_KALI = '<span class="p">kali@kali<i>:~</i>$</span> ';
  var PROMPT_ROOT = '<span class="root">root@target<i>:/</i>#</span> ';

  // A scripted "session". type = shows characters one by one; out = prints line.
  var SCRIPT = [
    { type: 'nc -lvnp 1337', prompt: PROMPT_KALI },
    { out: '<span class="out">listening on [any] 1337 ...</span>', wait: 1600 },
    { out: '<span class="out">connect to [10.10.14.8] from (UNKNOWN) [10.129.2.14] 49822</span>', wait: 600 },
    { type: 'whoami', prompt: PROMPT_ROOT },
    { out: '<span class="ok">root</span>', wait: 500 },
    { type: 'id', prompt: PROMPT_ROOT },
    { out: '<span class="out">uid=0(root) gid=0(root) groups=0(root)</span>', wait: 500 },
    { type: 'cat /root/proof.txt', prompt: PROMPT_ROOT },
    { out: '<span class="hi">7f3a9c1e2b8d4f60a5c7e9b1d3f5a7c9</span>', wait: 700 },
    { out: '<span class="out">[+] host compromised &mdash; documenting findings...</span>', wait: 3600 },
    { clear: true }
  ];

  var lines = [];       // finished lines (html)
  var current = '';     // line being typed (text)
  var currentPrompt = '';
  var stepIdx = 0;
  var timer;
  var MAX_LINES = 12;

  function render() {
    var html = lines.map(function (l) { return '<div class="tline">' + l + '</div>'; }).join('');
    html += '<div class="tline">' + currentPrompt + '<span class="cmd">' + escapeHtml(current) + '</span><span class="tcursor" aria-hidden="true"></span></div>';
    root.innerHTML = html;
    root.scrollTop = root.scrollHeight;
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  }

  function pushLine(html) {
    lines.push(html);
    if (lines.length > MAX_LINES) lines.shift();
  }

  function next() {
    if (!fxOn()) { timer = setTimeout(next, 1000); return; }
    var s = SCRIPT[stepIdx % SCRIPT.length];
    stepIdx++;

    if (s.clear) {
      lines = []; current = ''; currentPrompt = PROMPT_KALI; render();
      timer = setTimeout(next, 900);
      return;
    }
    if (s.out) {
      pushLine(s.out);
      render();
      timer = setTimeout(next, s.wait || 400);
      return;
    }
    if (s.type) {
      currentPrompt = s.prompt;
      current = '';
      var i = 0;
      (function typeChar() {
        if (i < s.type.length) {
          current = s.type.slice(0, ++i);
          render();
          timer = setTimeout(typeChar, 45 + Math.random() * 70);
        } else {
          timer = setTimeout(function () {
            pushLine(s.prompt + '<span class="cmd">' + escapeHtml(s.type) + '</span>');
            current = '';
            currentPrompt = '';
            render();
            timer = setTimeout(next, 350);
          }, 400);
        }
      })();
    }
  }

  currentPrompt = PROMPT_KALI;
  render();
  timer = setTimeout(next, 900);
})();
