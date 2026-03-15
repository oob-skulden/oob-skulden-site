(function () {
  var PROMPT_TEMPLATE =
    'Fetch {URL} and walk me through it step by step as an interactive session. ' +
    'Rules: (1) Start by briefly stating what the post covers and how many major steps or sections there are. ' +
    '(2) Present one step at a time. Give me the exact commands, explain what each does before I run it, and tell me what output to expect. ' +
    '(3) After each step, wait for me to say "next" or ask a question before continuing. ' +
    '(4) If I paste terminal output, tell me whether it matches expected output and whether it is safe to proceed. ' +
    '(5) If the post documents things that did not work, include those as warnings when we reach the relevant step -- do not skip them. ' +
    '(6) At the end, summarize what was accomplished and list any remediation steps covered. ' +
    'Start now with the overview.';

  function buildPrompt(url) {
    return PROMPT_TEMPLATE.replace('{URL}', url);
  }

  function initWalkthrough() {
    var blocks = document.querySelectorAll('.ai-walkthrough-block');
    blocks.forEach(function (block) {
      var url = block.getAttribute('data-url');
      var btn = block.querySelector('.ai-walkthrough-btn');
      var confirm = block.querySelector('.ai-walkthrough-confirm');
      var toggle = block.querySelector('.ai-walkthrough-toggle');
      var preview = block.querySelector('.ai-walkthrough-preview');

      if (!btn || !url) return;

      var prompt = buildPrompt(url);

      if (preview) {
        preview.textContent = prompt;
      }

      if (toggle && preview) {
        ['click', 'touchend'].forEach(function (evt) {
          toggle.addEventListener(evt, function (e) {
            e.preventDefault();
            var expanded = preview.classList.contains('ai-walkthrough-preview--visible');
            if (expanded) {
              preview.classList.remove('ai-walkthrough-preview--visible');
              toggle.textContent = 'inspect prompt';
              toggle.setAttribute('aria-expanded', 'false');
            } else {
              preview.classList.add('ai-walkthrough-preview--visible');
              toggle.textContent = 'collapse prompt';
              toggle.setAttribute('aria-expanded', 'true');
            }
          });
        });
      }

      btn.addEventListener('click', function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(prompt).then(function () {
            showConfirm(confirm, btn);
          }).catch(function () {
            fallbackCopy(prompt, confirm, btn);
          });
        } else {
          fallbackCopy(prompt, confirm, btn);
        }
      });
    });
  }

  function fallbackCopy(text, confirm, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      document.execCommand('copy');
      showConfirm(confirm, btn);
    } catch (e) {
      confirm.textContent = 'Copy failed -- select and copy the prompt manually.';
    }
    document.body.removeChild(ta);
  }

  function showConfirm(confirm, btn) {
    btn.textContent = 'Copied';
    btn.classList.add('ai-walkthrough-copied');
    confirm.textContent = 'Prompt copied. Paste it into Claude, ChatGPT, or Gemini with web access enabled.';
    setTimeout(function () {
      btn.textContent = 'Copy walkthrough prompt';
      btn.classList.remove('ai-walkthrough-copied');
      confirm.textContent = '';
    }, 4000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWalkthrough);
  } else {
    initWalkthrough();
  }
})();
