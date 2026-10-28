const status = document.querySelector('#status');
const question = document.querySelector('#question');
const copyButton = document.querySelector('#copy');
let site;
const requested = new URLSearchParams(location.search).get('site');
if (requested) {
  const u = new URL(requested);
  const whole = tldts.getDomain(u.hostname, {allowPrivateDomains: true}) === u.hostname;
  question.textContent = `Your AI needs your ${u.host} login${whole ? ', including every subdomain' : ''}. Copy it?`;
  document.querySelector('#options').hidden = true;
  const deny = document.querySelector('#deny');
  deny.hidden = false;
  copyButton.onclick = () => chrome.runtime.sendMessage({op: 'allow', answer: true});
  deny.onclick = () => chrome.runtime.sendMessage({op: 'allow', answer: false});
} else {
  chrome.tabs.query({active: true, currentWindow: true}).then(([tab]) => {
    const u = tab?.url ? new URL(tab.url) : null;
    if (u && ['http:', 'https:'].includes(u.protocol)) {
      site = u.origin;
      const whole = tldts.getDomain(u.hostname, {allowPrivateDomains: true});
      question.textContent = `Copy ${whole ? whole + ' and every subdomain' : u.host} to your AI browser?`;
    } else {
      question.textContent = 'Open a website to copy it.';
      copyButton.hidden = true;
    }
  });
  copyButton.onclick = async () => {
    copyButton.disabled = true;
    status.textContent = 'Copying...';
    try {
      const result = await chrome.runtime.sendMessage({op: 'copy', origin: site});
      status.textContent = result?.ok ? `Copied ${result.count} cookies.` : result?.error === 'Busy' ? 'Busy, try again in a moment.' : result?.error === 'Not connected' ? 'Connect an ai app first.' : 'Copy failed.';
    } catch (_) {
      status.textContent = 'Copy failed.';
    } finally {
      copyButton.disabled = false;
    }
  };
  document.querySelector('#options').onclick = () => chrome.runtime.openOptionsPage();
}
