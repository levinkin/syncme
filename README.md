# syncme

copies your logins for a site from your normal chrome into a separate chrome that ai agents and scripts can drive. so jev, browser-use or playwright can use your accounts without touching your real browser.

syncme comes in two parts: the [chrome extension](https://chromewebstore.google.com/detail/dcgmgkdgmbjgnchjdmokimppnhfinpfp) and [syncme-mcp](https://www.npmjs.com/package/syncme-mcp), the npm bridge it talks to. the source for both is on [github](https://github.com/levinkin/syncme).

## how it works

1. when you're on a site you want, click the syncme icon and it asks if you want to copy it over
2. syncme grabs that site's cookies and puts them in its own chrome profile (the "ai browser"). this runs headless in the background, nothing pops up
3. when a script needs the browser, run `npx -y syncme-mcp open`. the ai browser opens as normal chrome with your logins already in it and prints a cdp url to connect to

it only copies cookies for sites you said yes to. no passwords, no other sites. syncme never touches your real chrome profile.

there's also a setting to re-copy all your saved sites every time the ai browser starts, so logins stay fresh.

## setup

needs chrome and node 20 or newer. works on mac and windows.

there's nothing to install: the extension talks to the bridge over a websocket on 127.0.0.1, and any command starts the bridge itself.

1. install the extension from the [chrome web store](https://chromewebstore.google.com/detail/dcgmgkdgmbjgnchjdmokimppnhfinpfp), or load this folder unpacked from `chrome://extensions` with developer mode on
2. click the syncme icon, hit the gear, and use one of the connect buttons, or run `npx -y syncme-mcp setup` to wire up claude code, codex, cursor, windsurf and claude desktop

## commands

```
npx -y syncme-mcp open                       # start the ai browser, prints {"cdp": "http://127.0.0.1:<port>"}
npx -y syncme-mcp sync https://example.com   # copy one site, asks you in chrome first unless it's saved or yolo is on
npx -y syncme-mcp stop                       # close the ai browser
npx -y syncme-mcp shutdown                   # close it and stop the bridge
npx -y syncme-mcp setup                      # add the mcp server to the ai apps you have installed
npx -y syncme-mcp unpair                     # forget the paired extension, for when you reinstall it
npx -y syncme-mcp pack                       # build syncme.zip for the web store
```

connecting from playwright:

```js
import {chromium} from 'playwright-core';
import {execFileSync} from 'node:child_process';

const {cdp} = JSON.parse(execFileSync('npx', ['-y', 'syncme-mcp', 'open']));
const browser = await chromium.connectOverCDP(cdp);
await (await browser.contexts()[0].newPage()).goto('https://example.com');
```

## mcp

you can also hook it up as an mcp server so your ai can ask for a site itself. it calls `copy_site` with something like `https://github.com`, you get a popup in chrome asking if it can have that login, and if you say yes it copies it and gets back the cdp url. turn on yolo mode in the syncme options (the gear in the popup) to skip that popup and let your ai copy any site it asks for. there's also `open_browser` and `close_browser`.

```
claude mcp add --scope user syncme -- npx -y syncme-mcp
codex mcp add syncme -- npx -y syncme-mcp
npx -y syncme-mcp setup   # does both of the above, plus the json configs
```

or by hand:

```json
{
  "mcpServers": {
    "syncme": {
      "command": "npx",
      "args": ["-y", "syncme-mcp"]
    }
  }
}
```

keep chrome open with the extension for it to work, since syncme takes the cookies from there.

## notes

- the ai browser profile lives in `~/Library/Application Support/syncme` on mac, `%LOCALAPPDATA%\syncme` on windows and `~/.local/state/syncme` on linux
- removing a site from the list stops future copies, but the ai browser keeps cookies it already has
- the extension and syncme pair the first time they connect and check each other after that, so other accounts on your computer can't pose as either one
- the bridge listens only on `127.0.0.1:47621`, only accepts a websocket whose origin is this extension, and only takes commands from a local token only your user can read

## license

[PolyForm Noncommercial 1.0.0](LICENSE). free to use, change and share for anything that isn't commercial. if you want to use it for a business, ask me.
