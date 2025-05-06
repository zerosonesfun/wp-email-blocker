document.addEventListener('DOMContentLoaded', function () {
  // Regex patterns for validation
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$/;
  const emailRegex  = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Elements for domains
  const domainTextarea   = document.getElementById('blocked-domains-textarea');
  const domainInput      = document.getElementById('pill-input');
  const domainContainer  = document.getElementById('blocked-domains-pills');

  // Elements for emails
  const emailTextarea    = document.getElementById('blocked-emails-textarea');
  const emailInput       = document.getElementById('email-pill-input');
  const emailContainer   = document.getElementById('blocked-emails-pills');

  // Initialize both
  if (domainTextarea && domainInput && domainContainer) {
    setupPillInput(domainTextarea, domainInput, domainContainer, domainRegex);
  }
  if (emailTextarea && emailInput && emailContainer) {
    setupPillInput(emailTextarea, emailInput, emailContainer, emailRegex);
  }

  // Final sync on form submit
  const form = document.querySelector('form');
  if (form) {
    form.addEventListener('submit', function () {
      syncTextarea(domainContainer, domainTextarea);
      syncTextarea(emailContainer, emailTextarea);
    });
  }

  // ——— Generic setup for one pill-field
  function setupPillInput(textarea, input, container, validateRegex) {
    // create a pill element
    function createPill(value) {
      const pill = document.createElement('span');
      pill.className = 'pill';
      pill.appendChild(document.createTextNode(value));

      const closeBtn = document.createElement('button');
      closeBtn.type = 'button';
      closeBtn.className = 'pill-close';
      closeBtn.textContent = '×';
      closeBtn.setAttribute('aria-label', 'Remove ' + value);
      closeBtn.title = 'Remove ' + value;
      closeBtn.addEventListener('click', () => {
        container.removeChild(pill);
        syncTextarea(container, textarea);
      });

      pill.appendChild(closeBtn);
      return pill;
    }

    // extract just the text node from a pill
    function getPillValue(pill) {
      return pill.firstChild.nodeValue.trim();
    }

    // add a new pill (if valid, non-duplicate)
    function addValue(raw) {
      const value = raw.trim();
      if (!value) return;
      // validate format
      if (!validateRegex.test(value)) return;
      // no dupes
      const found = Array.from(container.children).some(
        c => getPillValue(c).toLowerCase() === value.toLowerCase()
      );
      if (found) return;
      // create + append
      container.appendChild(createPill(value));
      syncTextarea(container, textarea);
    }

    // initial population from textarea
    textarea.value.split('\n').forEach(line => addValue(line));

    // Enter key on the input
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        addValue(input.value);
        input.value = '';
      }
    });
  }

  // sync a container back into its hidden textarea
  function syncTextarea(container, textarea) {
    const all = Array.from(container.children).map(getPillValue);
    textarea.value = all.join('\n');
  }

  // helper reused
  function getPillValue(pill) {
    return pill.firstChild.nodeValue.trim();
  }
});