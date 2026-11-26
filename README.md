# GLKVM KVMD

GLKVM KVMD is a derivative project based on the open-source [PiKVM](https://github.com/pikvm/pikvm). We would like to express our sincere gratitude to the PiKVM team for their outstanding contributions to the open-source community.

## About This Fork

This fork enhances the original GLKVM Paste as Keys functionality to address issues where pasting large amounts of text could fail, time out, or stop before completion.

The improved implementation supports longer text-pasting operations through extended request timeouts, configurable typing speeds, randomized pauses, and interactive typing controls.

### Features

- **Long-text pasting:** Supports extended paste operations by reducing premature request timeouts.
- **Original typing behavior:** Preserves the original normal and slow typing speeds when the additional typing options are disabled.
- **Variable typing:** Introduces random pauses between characters, with a 0.5% probability per character boundary and randomized pause durations of up to 30 seconds.
- **Super variable typing:** Randomly adjusts the selected typing speed by ±25%.
- **Custom typing speed:** Allows users to specify their preferred typing speed in words per minute (WPM).
- **Pause and resume:** Allows users to pause an ongoing paste operation and resume from the same position.
- **Live settings:** Allows typing preferences to be changed during a pause and applied when typing resumes.
- **Information icons:** Provides descriptions of each typing option through hover and click interactions.
- **Macro compatibility:** Supports recording and replaying the additional typing settings.
- **Privacy:** All typing calculations are performed locally, without introducing external services, telemetry, or data collection.

These enhancements preserve the original USB HID keyboard implementation and keyboard layout handling, without intentionally changing hardware identification. Text continues to be transmitted as keyboard press and release events rather than through the connected computer's clipboard.

The goal of this fork is to make pasting long text more reliable, flexible, and configurable while maintaining the original GLKVM functionality. Unlimited paste length is not guaranteed.

## License

GLKVM KVMD is released under the [GPL V3](https://github.com/gl-inet/glkvm/blob/main/LICENSE) license. As a derivative project of PiKVM, we are committed to complying with all terms of the GPL V3 license.

## About KVMD

KVMD is the core daemon of GLKVM/PiKVM. This repository contains the configuration and code of KVMD. If you have any questions not directly related to this codebase, please submit them to the [GLKVM](https://github.com/gl-inet/glkvm/issues) repository.

## Firmware Download

If you want to download the latest or previous firmware, please visit: https://dl.gl-inet.com/kvm/rm1/stable

## Synchronize kvmd changes to the device

When you modify the contents of the kvmd folder and want to synchronize it to the kvm device, you can do so by executing the **apply_to_glkvm.sh** script (note: it needs to be in the same LAN as the kvm device). After execution, you need to restart the kvm device.

With your computer and Comet connected to the same Wi-Fi or local network, open Terminal in the full source directory and run:

```sh
bash ./apply_to_glkvm.sh
```

This installs the Python code in the `kvmd/` directory on the Comet, including `hid.py` and `printer.py`. The remaining files must be transferred manually using SCP. From the same source directory, run:

```sh
scp web/kvm/index.html root@glkvm.local:/usr/share/kvmd/web/kvm/index.html
scp web/share/js/kvm/paste.js root@glkvm.local:/usr/share/kvmd/web/share/js/kvm/paste.js
scp web/share/js/kvm/recorder.js root@glkvm.local:/usr/share/kvmd/web/share/js/kvm/recorder.js
scp configs/nginx/kvmd.ctx-server.conf root@glkvm.local:/etc/kvmd/nginx/kvmd.ctx-server.conf
```

### Enable the native KVMD web interface

In the GLKVM device terminal, open the NGINX configuration:

```sh
cd /etc/kvmd
nano nginx-kvmd.conf
```

Find the commented-out HTTPS server block for port `8888` and remove the leading `#` from each line of that block so it looks like this:

```nginx
server {
    listen 8888 ssl;
    listen [::]:8888 ssl;
    http2 on;
    include /etc/kvmd/nginx/ssl.conf;
    include /etc/kvmd/nginx/kvmd.ctx-server.conf;
    include /usr/share/kvmd/extras/*/nginx.ctx-server.conf;
    location /connect {
        return 301 /;
    }
}
```

Save the file in Nano with **Ctrl+O**, press **Enter**, then exit with **Ctrl+X**. Keep this interface on a trusted local network; do not forward port 8888 to the internet.

Restart the Comet after all files have been transferred and the configuration has been saved. Open the native KVMD interface at [https://glkvm.local:8888](https://glkvm.local:8888).

## Custom Paste as Keys enhancements (unofficial)

This modified source adds optional typing controls to the native KVMD web interface. It is not an official GL.iNet firmware release. The changes schedule existing USB keyboard events; they do not intentionally change USB descriptors, mouse handling, HDMI EDID, video streaming, or cloud services.

### Typing options

| Option | Behavior |
| --- | --- |
| All options off | Original normal timing: 5 ms per HID key event. |
| Slow typing | Original slow timing: 30 ms per HID key event. |
| Variable typing | Independent 0.5% chance of a pause before each character after the first; duration uniformly selected from 0.1–30 seconds. Mean interval is 200 character boundaries, not a fixed interval. |
| Super variable typing | Varies the selected baseline rate by ±25% per character. Normal event delay becomes 4–6.67 ms; slow becomes 24–40 ms. |
| Custom typing speed | Overrides normal/slow with a target of 1–1000 integer WPM (default 75). Uses five characters per word. |
| Custom + Super variable | Random target between 75% and 125% of entered WPM (e.g. 80 WPM gives 60–100 WPM). |

Variable pauses can be combined with any speed mode. Custom speed overrides Slow; Super variable modifies whichever speed is selected. Real throughput can differ due to HID overhead, modifiers, scheduling and pauses. The original legacy API path is retained for requests without a session ID or additional modes; browser sessions use character batches even with all switches off to support live pause/resume.

Click Paste to start; the menu closes automatically. Reopen the Text menu and click **Pause typing** to stop at a character boundary. Change the switches or custom speed and click **Resume typing** to continue with the latest settings. Changes are also sent during an active paste, including automatic pauses; an existing timed pause may finish first. Manual pauses are not subject to the 30-second automatic limit. Hover over an information icon for a tooltip or click it for a description. Typing preferences are saved in browser storage.

### Modified files

| Source path | Changes |
| --- | --- |
| `kvmd/apps/kvmd/api/hid.py` | Paste session tracking, timing, random pauses, live settings, validation and pause/resume endpoint. Rejects simultaneous paste requests (409). |
| `kvmd/keyboard/printer.py` | Adds character-batched keyboard event conversion while retaining the original public conversion function and mapping logic. |
| `web/kvm/index.html` | Adds switches, conditional WPM input, pause/resume and help icons; retains automatic menu closing. |
| `web/share/js/kvm/paste.js` | Persists preferences, sends settings and session IDs, handles pause/resume and revisioned updates; removes plaintext paste content from debug logs. |
| `web/share/js/kvm/recorder.js` | Records and replays initial typing options, with compatibility for older macros. Manual pause durations and later edits are not recorded. |
| `configs/nginx/kvmd.ctx-server.conf` | Exact matching for `/api/hid/print` and seven-day proxy read timeout. The general `/api` route forwards `/api/hid/print_pause`. |

The new endpoint is `POST /api/hid/print_pause`; the existing `/api/hid/print` receives text plus optional `slow`, `variable`, `super_variable`, `speed` (0 means preset), and `paste_id` query parameters. Settings updates use a revision number. Resume includes the latest settings. The backend releases held modifiers during a pause and restores them before continuing. To adjust the pause frequency or duration, inspect `__type_text` in `hid.py` (`random.random() < 0.005`, `random.uniform(0.1, 30.0)`).

### Privacy and limitations

No new external service or telemetry is introduced in these six source changes. Text is sent through the existing KVM connection, retained in memory during a paste, and converted to USB HID events. Use HTTPS on trusted networks. Hide input text is visual masking, not encryption. Macros may contain plaintext; session identifiers and settings may appear in access logs. The new pause endpoint uses existing authentication but does not explicitly bind session IDs to the originating authenticated user. Long requests can retain resources for longer. This is not a complete security audit or a guarantee of identical firmware privacy properties. USB/HDMI identity was not intentionally changed; actual hardware behavior has not been verified.
