const status = document.querySelector('#status');
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
for (const [id, key] of [['auto', 'autoSync'], ['yolo', 'yolo']]) {
  const box = document.querySelector('#' + id);
  chrome.storage.local.get(key).then(stored => { box.checked = stored[key] === true; });
  box.onchange = () => chrome.storage.local.set({[key]: box.checked});
}
document.querySelector('#claude').onclick = () => navigator.clipboard.writeText('claude mcp add syncme -- npx -y syncme-mcp@latest');
document.querySelector('#setup').onclick = () => navigator.clipboard.writeText('npx -y syncme-mcp@latest setup');
chrome.storage.session.get(['connected', 'pairing']).then(({connected, pairing}) => {
  document.querySelector('#waiting').hidden = connected === true || Boolean(pairing);
  const box = document.querySelector('#pairing');
  box.hidden = !pairing;
  box.firstChild.textContent = pairing === 'lost' ? 'syncme lost its pairing with this extension.' : 'syncme is paired with a different extension. Run npx -y syncme-mcp@latest unpair, then hit Re-pair.';
});
document.querySelector('#repair').onclick = () => { chrome.runtime.sendMessage({op: 'repair'}); document.querySelector('#pairing').hidden = true; };
chrome.storage.onChanged.addListener(changes => { if (changes.approved) render(); });
render();
