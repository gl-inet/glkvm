# GLKVM paste hook

## What it does

While the KVM video stream has focus, **Cmd+V** (macOS) or **Ctrl+V** (other
systems) types the *local* clipboard text into the remote host. It works in the
GLKVM desktop app and in any browser opening the device UI, and it uses the
device's existing `/api/hid/print` endpoint (the same one behind the UI's
"paste as keystrokes" dialog). Nothing in kvmd itself is changed.

## How it works

- `paste-hook.js` is added to the web UI by a `<script>` tag in
  `/usr/share/kvmd/glweb/index.html`, loaded before the UI's own module bundle.
- It registers capture-phase keyboard and `paste` listeners, so it sees the
  shortcut before the UI forwards it to the remote host as a keystroke.
- The text comes from the browser's native `paste` event (no clipboard
  permission prompt), and is sent to `/api/hid/print`.
- By the time V is pressed, the Meta (Cmd/Win) key has already been forwarded
  to the remote host. A remote Windows machine would open the Start menu when
  Meta is released, so the hook sends a short Ctrl tap to cancel it.
- Typing starts only after you release the modifier key (or after 1.5 s, in
  which case the hook releases it on the remote itself), so the text is never
  typed with Win/Ctrl still held down on the remote host.

## Install / Remove / Status

From a Mac or Linux machine with OpenSSH (you are asked for the root password
by ssh; the script never stores or reads it):

```sh
contrib/paste-hook/apply_paste_hook.sh install
contrib/paste-hook/apply_paste_hook.sh status
contrib/paste-hook/apply_paste_hook.sh remove

# a different device address or SSH port:
GLKVM_HOST=192.168.8.123 GLKVM_PORT=22 contrib/paste-hook/apply_paste_hook.sh install
```

### Windows

From Windows 10/11 with the built-in OpenSSH client (Settings > System >
Optional features > "OpenSSH Client"), in PowerShell 5.1 or 7:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\contrib\paste-hook\apply_paste_hook.ps1 install
.\contrib\paste-hook\apply_paste_hook.ps1 status
.\contrib\paste-hook\apply_paste_hook.ps1 remove

# or without changing the policy, and with a different address:
$env:GLKVM_HOST = '192.168.8.123'
powershell -ExecutionPolicy Bypass -File contrib\paste-hook\apply_paste_hook.ps1 install
```

Windows OpenSSH cannot share one connection between steps, so ssh asks for
the root password once per connection (twice for `install` and `remove`,
once for `status`); an SSH key avoids the prompts. The script never stores or
reads the password. `contrib/paste-hook/.gitattributes` keeps the device-side
files checked out with LF, and the script also strips CRs on the device after
upload.

`install` copies the files to the device, activates the hook immediately and
prints a check (`grep -c paste-hook .../index.html` should print `1`). Then
**hard-reload** the UI (Cmd+Shift+R, or restart the GLKVM app). No reboot is
needed. `remove` undoes everything and checks that `index.html` matches the
firmware original again.

Installed files:

| File | Purpose |
|------|---------|
| `/etc/kvmd/user/paste-hook/paste-hook.js` | the script (persistent master copy) |
| `/etc/kvmd/user/scripts/S90paste-hook.sh` | boot hook, run by `/etc/init.d/S99custom` |
| `/usr/share/kvmd/glweb/paste-hook.js`, `index.html` | regenerated at every boot |

## Client shortcut

| Client OS | Paste shortcut |
|-----------|----------------|
| macOS | Cmd+V |
| Windows / Linux | Ctrl+V |

Cmd+Shift+V / Ctrl+Shift+V are not intercepted and are still forwarded as
keystrokes to the remote host, so a remote-side paste is still possible.

Tested end-to-end only from a macOS client. Windows/Linux clients use the same
code path (the Ctrl+V keydown reaches the page, and Chromium's native paste
then fires the `paste` event the hook reads), but this has not been tested
from a Windows workstation yet.

## Persistence and firmware upgrades

The root filesystem is an overlay: the firmware is a read-only squashfs at
`/rom`, and every change made under `/` is stored in the writable layer
`/userdata/overlay/upper`. A file edited in place would keep shadowing the
firmware's version after an upgrade, which could break the UI once the new
firmware ships different asset names.

So the hook never keeps a hand-edited file. At every boot, `S99custom` runs
`/etc/kvmd/user/scripts/S90paste-hook.sh start`, which:

1. rebuilds `index.html` from the pristine `/rom/usr/share/kvmd/glweb/index.html`
   by inserting one `<script src="./paste-hook.js?v=<hash>">` before `</head>`
   (written to a temp file, then moved into place; running it twice still
   gives exactly one tag);
2. copies `paste-hook.js` into the web directory (the `?v=` hash busts caches
   when the script changes);
3. **self-disables**: if the master script is missing, or the firmware
   `index.html` is missing, has no `</head>`, or the result does not verify, it
   deletes its overlay copies so the firmware original is served unchanged.

Upgrades with **"save config"** keep the overlay, so the hook survives and
re-patches the new firmware's `index.html` on the first boot. An upgrade
**without** save-config, or a factory reset, wipes the overlay: the hook is
gone and you need to run `install` again.

## Caveats

- The keymap selected in the KVM UI must match the remote host's keyboard
  layout, otherwise characters come out wrong (as with any `/api/hid/print`).
- Characters that would need a Ctrl chord are skipped by kvmd.
- Tabs and newlines are typed literally (Tab/Enter), which can move focus or
  submit forms on the remote side.
- With the stream focused, Cmd+V can no longer be sent as a keystroke to a
  **macOS** remote host; Cmd+Shift+V still is.
- Long texts are typed at HID speed and take a while; avoid typing on the
  remote while it runs.
- After install or remove, hard-reload the UI; an already open page keeps the
  old `index.html`.

## Uninstall by hand

Over SSH on the device:

```sh
sh /etc/kvmd/user/scripts/S90paste-hook.sh remove
rm -f /etc/kvmd/user/scripts/S90paste-hook.sh
rm -rf /etc/kvmd/user/paste-hook
```

Without the hook script, delete these three paths and reboot:

- `/etc/kvmd/user/scripts/S90paste-hook.sh` and `/etc/kvmd/user/paste-hook/`
- `/usr/share/kvmd/glweb/paste-hook.js`
- `/userdata/overlay/upper/usr/share/kvmd/glweb/index.html` (the patched
  copy; delete it in the upper layer, not via `/usr/...`, so the `/rom`
  original reappears instead of being hidden by an overlay whiteout)
