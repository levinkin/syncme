const status = document.querySelector('#status');
const question = document.querySelector('#question');
const copyButton = document.querySelector('#copy');
const auto = document.querySelector('#auto');
let site;
async function render() {
  const {approved = []} = await chrome.storage.local.get('approved');
  const list = document.querySelector('#approved');
  list.replaceChildren();
  for (const value of approved) {
    const li = document.createElement('li');
    li.append(document.createTextNode(new URL(value).host));
    const button = document.createElement('button');
    button.textContent = 'Remove';
    button.onclick = async () => {
      const {approved = []} = await chrome.storage.local.get('approved');
      await chrome.storage.local.set({approved: approved.filter(x => x !== value)});
      status.textContent = 'Removed. The AI browser keeps cookies it already has.';
      await render();
    };
    li.append(button); list.append(li);
  }
}
const requested = new URLSearchParams(location.search).get('site');
if (requested) {
  question.textContent = `Your AI wants your ${new URL(requested).host} login. Copy it?`;
  document.querySelector('#settings').hidden = true;
  const deny = document.querySelector('#deny');
  deny.hidden = false;
  copyButton.onclick = () => chrome.runtime.sendMessage({op: 'allow', answer: true});
  deny.onclick = () => chrome.runtime.sendMessage({op: 'allow', answer: false});
} else chrome.tabs.query({active: true, currentWindow: true}).then(([tab]) => {
  const u = tab?.url ? new URL(tab.url) : null;
  if (u && ['http:', 'https:'].includes(u.protocol)) {
    site = u.origin;
    question.textContent = `Copy ${u.host} to your AI browser?`;
  } else {
    question.textContent = 'Open a website to copy it.';
    copyButton.hidden = true;
  }
});
if (!requested) copyButton.onclick = async () => {
  copyButton.disabled = true;
  status.textContent = 'Copying...';
  try {
    const result = await chrome.runtime.sendMessage({op: 'copy', origin: site});
    status.textContent = result?.ok ? `Copied ${result.count} cookies.` : result?.error === 'Busy' ? 'Busy, try again in a moment.' : 'Copy failed. If this is a new setup, run syncme.py install.';
  } catch (_) {
    status.textContent = 'Copy failed. If this is a new setup, run syncme.py install.';
  } finally {
    copyButton.disabled = false;
  }
  await render();
};
chrome.storage.local.get('autoSync').then(({autoSync}) => { auto.checked = autoSync === true; });
auto.onchange = () => chrome.storage.local.set({autoSync: auto.checked});
render();
