/* ══════════════════════════════════════════════════════════
   Food Truck Rewards — "how are we doing?" review widget
   ──────────────────────────────────────────────────────────
   Drop this on any page:

     <div data-ftr-feedback data-role="vendor"></div>
     <script src="/feedback.js" defer></script>

   Optional attributes:
     data-role   vendor | customer | visitor   (default visitor)
     data-name   pre-filled name
     data-email  pre-filled email
     data-compact  "1" → tighter padding for in-app cards

   Colours come from CSS custom properties set on the container,
   so the same widget sits correctly on the cream website and
   inside the dark-on-light app:
     --fb-bg  --fb-line  --fb-ink  --fb-mu  --fb-accent  --fb-radius
   ══════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var STAR_LABELS = ['Rough', 'Needs work', 'Okay', 'Good', 'Love it'];

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function build(box) {
    if (box.dataset.ftrReady) return;
    box.dataset.ftrReady = '1';

    var role    = box.getAttribute('data-role') || 'visitor';
    var compact = box.getAttribute('data-compact') === '1';
    var pad     = compact ? '16px' : '22px';
    // The site had a small-type problem; the star row is the one thing
    // everybody uses, so give it room on the full-size version.
    var lblSize = compact ? '13.5px' : '15.5px';
    var starSz  = compact ? '31px'   : '38px';
    var uid     = 'fb' + Math.random().toString(36).slice(2, 8);
    var state   = { rating: 0, sending: false, done: false };

    box.innerHTML =
      '<div class="ftr-fb" style="background:var(--fb-bg,#fff);border:1.5px solid var(--fb-line,#f0e4d6);' +
        'border-radius:var(--fb-radius,18px);padding:' + pad + ';color:var(--fb-ink,#14100C);text-align:left">' +

        '<div id="' + uid + '-form">' +
          '<div style="font-size:' + lblSize + ';font-weight:900;color:var(--fb-mu,#7a6a5c);margin-bottom:8px">' +
            'How would you rate it so far?</div>' +
          '<div id="' + uid + '-stars" role="radiogroup" aria-label="Rating" ' +
            'style="display:flex;gap:6px;margin-bottom:6px">' +
            [1, 2, 3, 4, 5].map(function (n) {
              return '<button type="button" data-star="' + n + '" role="radio" aria-checked="false" ' +
                'aria-label="' + n + ' star' + (n === 1 ? '' : 's') + ' — ' + esc(STAR_LABELS[n - 1]) + '" ' +
                'style="font-size:' + starSz + ';line-height:1;background:none;border:none;padding:2px 1px;cursor:pointer;' +
                'color:#d9cfc4;-webkit-tap-highlight-color:transparent;outline:none;' +
                'transition:transform .12s,color .12s">&#9733;</button>';
            }).join('') +
          '</div>' +
          '<div id="' + uid + '-lbl" style="font-size:13px;font-weight:800;color:var(--fb-accent,#FF5722);' +
            'min-height:19px;margin-bottom:12px">&nbsp;</div>' +

          '<textarea id="' + uid + '-msg" rows="4" maxlength="2000" ' +
            'placeholder="What&rsquo;s working? What&rsquo;s missing or confusing? Anything you&rsquo;d change?" ' +
            'style="width:100%;box-sizing:border-box;font:inherit;font-size:16px;font-weight:700;line-height:1.5;' +
            'padding:13px 14px;border:1.5px solid var(--fb-line,#f0e4d6);border-radius:12px;background:#fff;' +
            'color:var(--fb-ink,#14100C);resize:vertical;outline:none"></textarea>' +

          '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));gap:10px;margin-top:10px">' +
            '<input id="' + uid + '-name" type="text" maxlength="120" placeholder="Your name (optional)" ' +
              'style="width:100%;box-sizing:border-box;font:inherit;font-size:16px;font-weight:700;padding:12px 14px;' +
              'border:1.5px solid var(--fb-line,#f0e4d6);border-radius:12px;background:#fff;color:var(--fb-ink,#14100C);outline:none">' +
            '<input id="' + uid + '-email" type="email" maxlength="200" autocomplete="email" ' +
              'placeholder="Email (only if you want a reply)" ' +
              'style="width:100%;box-sizing:border-box;font:inherit;font-size:16px;font-weight:700;padding:12px 14px;' +
              'border:1.5px solid var(--fb-line,#f0e4d6);border-radius:12px;background:#fff;color:var(--fb-ink,#14100C);outline:none">' +
          '</div>' +

          '<button type="button" id="' + uid + '-send" ' +
            'style="margin-top:14px;width:100%;font:inherit;font-size:17px;font-weight:900;padding:15px 20px;border:none;' +
            'border-radius:14px;background:var(--fb-accent,#FF5722);color:#fff;cursor:pointer">Send my review</button>' +

          '<div id="' + uid + '-status" style="font-size:13.5px;font-weight:800;margin-top:11px;min-height:19px"></div>' +
          '<div style="font-size:12.5px;font-weight:700;color:var(--fb-mu,#7a6a5c);margin-top:4px;line-height:1.55">' +
            'Goes straight to Sam, the person who builds this. ' +
            'Prefer email? <a href="mailto:flavoronwheels26@gmail.com" ' +
            'style="color:var(--fb-accent,#FF5722)">flavoronwheels26@gmail.com</a></div>' +
        '</div>' +

        '<div id="' + uid + '-thanks" hidden style="text-align:center;padding:14px 4px">' +
          '<div style="font-size:40px;line-height:1">&#127881;</div>' +
          '<div style="font-size:20px;font-weight:900;margin:8px 0 6px">Thank you &mdash; got it.</div>' +
          '<div style="font-size:15px;font-weight:700;color:var(--fb-mu,#7a6a5c);line-height:1.6">' +
            'I read every one of these, and it&rsquo;s how the next update gets decided.</div>' +
        '</div>' +
      '</div>';

    var stars  = box.querySelectorAll('[data-star]');
    var lbl    = box.querySelector('#' + uid + '-lbl');
    var msg    = box.querySelector('#' + uid + '-msg');
    var nameIn = box.querySelector('#' + uid + '-name');
    var mailIn = box.querySelector('#' + uid + '-email');
    var btn    = box.querySelector('#' + uid + '-send');
    var status = box.querySelector('#' + uid + '-status');

    if (box.getAttribute('data-name'))  nameIn.value = box.getAttribute('data-name');
    if (box.getAttribute('data-email')) mailIn.value = box.getAttribute('data-email');

    function paint(upTo) {
      for (var i = 0; i < stars.length; i++) {
        var lit = i < upTo;
        stars[i].style.color     = lit ? 'var(--fb-star,#F9A825)' : '#d9cfc4';
        stars[i].style.transform = lit ? 'scale(1.06)' : 'scale(1)';
      }
    }

    for (var i = 0; i < stars.length; i++) {
      (function (b) {
        var n = parseInt(b.getAttribute('data-star'), 10);
        // Hover previews on a mouse; on touch the tap itself sets it, and
        // mouseenter never fires, so nothing is lost.
        b.addEventListener('mouseenter', function () { if (!state.done) paint(n); });
        b.addEventListener('click', function () {
          state.rating = n;
          paint(n);
          lbl.textContent = STAR_LABELS[n - 1];
          for (var j = 0; j < stars.length; j++) {
            stars[j].setAttribute('aria-checked', j === n - 1 ? 'true' : 'false');
          }
        });
      })(stars[i]);
    }
    box.querySelector('#' + uid + '-stars').addEventListener('mouseleave', function () {
      if (!state.done) paint(state.rating);
    });

    btn.addEventListener('click', async function () {
      if (state.sending) return;
      var text = (msg.value || '').trim();
      if (!state.rating && !text) {
        status.style.color = '#B02A37';
        status.textContent = 'Tap a star or write us a line first.';
        return;
      }
      state.sending = true;
      btn.disabled = true;
      btn.style.opacity = '.6';
      btn.textContent = 'Sending…';
      status.textContent = '';
      try {
        var res = await fetch('/api/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rating:  state.rating,
            message: text,
            name:    (nameIn.value || '').trim(),
            email:   (mailIn.value || '').trim(),
            role:    role,
            page:    location.pathname
          })
        });
        var data = null;
        try { data = await res.json(); } catch (e) {}
        if (!res.ok) throw new Error((data && data.error) || ('Error ' + res.status));
        state.done = true;
        box.querySelector('#' + uid + '-form').hidden = true;
        box.querySelector('#' + uid + '-thanks').hidden = false;
      } catch (ex) {
        status.style.color = '#B02A37';
        status.innerHTML = esc(ex.message) +
          '<br><a href="mailto:flavoronwheels26@gmail.com" style="color:#B02A37">Email it to me instead &rarr;</a>';
        state.sending = false;
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.textContent = 'Send my review';
      }
    });
  }

  function init() {
    var boxes = document.querySelectorAll('[data-ftr-feedback]');
    for (var i = 0; i < boxes.length; i++) build(boxes[i]);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  // The app builds screens after load, so let it re-scan on demand.
  window.ftrFeedbackInit = init;
})();
