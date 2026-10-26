# syncme

copies your logins for a site from your normal chrome into a separate chrome that ai agents and scripts can drive. so jev, browser-use or playwright can use your accounts without touching your real browser.

## how it works

1. when you're on a site you want, click the syncme icon and it asks if you want to copy it over
2. syncme grabs that site's cookies and puts them in its own chrome profile (the "ai browser"). this runs headless in the background, nothing pops up
3. when a script needs the browser, run `syncme.py open`. the ai browser opens as normal chrome with your logins already in it and prints a cdp url to connect to

it only copies cookies for sites you said yes to. no passwords, no other sites. syncme never touches your real chrome profile.

there's also a setting to re-copy all your saved sites every time the ai browser starts, so logins stay fresh.

## setup

needs chrome, python 3 and playwright (`pip install playwright`). works on mac and windows.

1. install the extension (chrome web store, or load this folder unpacked from `chrome://extensions` with developer mode on)
2. clone this repo and run `python3 syncme.py install`. this registers the local bridge the extension talks to
3. reload the extension

## commands

```
python3 syncme.py open                       # start the ai browser, prints {"cdp": "http://127.0.0.1:<port>"}
python3 syncme.py sync https://example.com   # copy one site, asks you in chrome first if it's not saved yet
python3 syncme.py stop                       # close the ai browser
python3 syncme.py shutdown                   # close it and stop the bridge
```

connecting from playwright:

```python
from playwright.sync_api import sync_playwright
import json, subprocess

cdp = json.loads(subprocess.check_output(['python3', 'syncme.py', 'open']))['cdp']
with sync_playwright() as pw:
    page = pw.chromium.connect_over_cdp(cdp).contexts[0].new_page()
    page.goto('https://example.com')
```

## mcp

you can also hook it up as an mcp server so your ai can ask for a site itself. it calls `copy_site` with something like `https://github.com`, you get a popup in chrome asking if it can have that login, and if you say yes it copies it and gets back the cdp url. there's also `open_browser` and `close_browser`.

```json
{
  "mcpServers": {
    "syncme": {
      "command": "python3",
      "args": ["/path/to/syncme/syncme.py", "mcp"]
    }
  }
}
```

keep chrome open with the extension for it to work, since syncme takes the cookies from there.

## notes

- the ai browser profile lives in `~/Library/Application Support/syncme` on mac and `%LOCALAPPDATA%\syncme` on windows
- removing a site from the list stops future copies, but the ai browser keeps cookies it already has
- the bridge only listens on 127.0.0.1 and only takes requests from the extension or from a local token only your user can read

## license

[PolyForm Noncommercial 1.0.0](LICENSE). free to use, change and share for anything that isn't commercial. if you want to use it for a business, ask me.
