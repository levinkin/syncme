const status = document.querySelector('#status');
async function render() {
  const {approved = []} = await chrome.storage.local.get('approved');
  const list = document.querySelector('#approved');
  list.replaceChildren();
  for (const value of approved) {
    const li = document.createElement('li');
    li.append(document.createTextNode(value + ' '));
    const button = document.createElement('button');
    button.textContent = 'Remove';
    button.onclick = async () => {
      await chrome.storage.local.set({approved: approved.filter(x => x !== value)});
      status.textContent = 'Removed. The syncme browser keeps cookies it already has until you clear them.';
      await render();
    };
    li.append(button); list.append(li);
  }
}
document.querySelector('#approve').onclick = async () => {
  try {
    const value = document.querySelector('#origin').value;
    const u = new URL(value);
    if (!['http:', 'https:'].includes(u.protocol) || u.origin !== value || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw Error('Enter just the site, like https://example.com, with no path or trailing slash.');
    const {approved = []} = await chrome.storage.local.get('approved');
    await chrome.storage.local.set({approved: [...new Set([...approved, value])]});
    await chrome.runtime.sendMessage({op: 'connect'});
    status.textContent = 'Added.'; await render();
  } catch (error) { status.textContent = error.message; }
};
const show = connected => { status.textContent = connected ? 'Connected.' : 'Not connected. Run syncme.py install, then click Connect.'; };
document.querySelector('#connect').onclick = async () => {
  status.textContent = 'Connecting...';
  await chrome.runtime.sendMessage({op: 'connect'});
  const {connected} = await chrome.storage.session.get('connected');
  if (connected) show(true);
};
chrome.storage.session.onChanged.addListener(changes => { if (changes.connected) show(changes.connected.newValue); });
chrome.storage.session.get('connected').then(({connected}) => show(connected));
render();
