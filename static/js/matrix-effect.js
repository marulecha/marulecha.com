/* Matrix rain — DPR aware, pauses when hidden, honours the FX toggle live. */
(function () {
  'use strict';

  var canvas = document.getElementById('matrix');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  var CHARS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン0123456789<>/\\|=+-*#$%&@';
  var FONT = 15;
  var cols = 0, drops = [], speeds = [];
  var raf = 0, last = 0, running = false;
  var INTERVAL = 55; // ms per step ~18fps: readable, cheap
  var C = {};

  function readTheme() {
    var cs = getComputedStyle(document.documentElement);
    var v = function (name, fb) { var x = cs.getPropertyValue(name).trim(); return x || fb; };
    C.bg = v('--bg', '#060910');
    C.fade = v('--matrix-fade', 'rgba(6,9,16,0.12)');
    C.head = v('--matrix-head', 'rgba(140,234,255,0.9)');
    C.headAlt = v('--matrix-head-alt', 'rgba(143,123,255,0.95)');
    C.trail = v('--matrix-trail', 'rgba(47,215,255,0.35)');
  }

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = window.innerWidth, h = window.innerHeight;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = FONT + 'px "IBM Plex Mono", ui-monospace, monospace';

    var newCols = Math.ceil(w / FONT);
    for (var i = cols; i < newCols; i++) {
      drops[i] = Math.floor(Math.random() * -(h / FONT));
      speeds[i] = 0.6 + Math.random() * 0.8;
    }
    cols = newCols;
    readTheme();
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, w, h);
  }

  function step(ts) {
    if (!running) return;
    raf = requestAnimationFrame(step);
    if (ts - last < INTERVAL) return;
    last = ts;

    var w = window.innerWidth, h = window.innerHeight;
    ctx.fillStyle = C.fade;
    ctx.fillRect(0, 0, w, h);

    for (var i = 0; i < cols; i++) {
      var y = drops[i] * FONT;
      if (y > 0) {
        var ch = CHARS.charAt((Math.random() * CHARS.length) | 0);
        // bright head, dimmer trail; occasional violet head for depth
        ctx.fillStyle = Math.random() < 0.06 ? C.headAlt : C.head;
        ctx.fillText(ch, i * FONT, y);
        ctx.fillStyle = C.trail;
        ctx.fillText(CHARS.charAt((Math.random() * CHARS.length) | 0), i * FONT, y - FONT);
      }
      if (y > h && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -20);
        speeds[i] = 0.6 + Math.random() * 0.8;
      }
      drops[i] += speeds[i];
    }
  }

  function start() {
    if (running) return;
    running = true;
    resize();
    last = 0;
    raf = requestAnimationFrame(step);
  }

  function stop() {
    running = false;
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
  }

  var resizeT;
  window.addEventListener('resize', function () {
    clearTimeout(resizeT);
    resizeT = setTimeout(function () { if (running) resize(); }, 120);
  });

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop();
    else if (window.SiteFX && window.SiteFX.enabled()) start();
  });

  if (window.SiteFX) {
    window.SiteFX.onChange(function (on) { on ? start() : stop(); });
    if (window.SiteFX.enabled()) start();
  } else {
    start();
  }
})();
