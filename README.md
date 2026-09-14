# GLKVM KVMD

GLKVM KVMD is a derivative project based on the open-source [PiKVM](https://github.com/pikvm/pikvm). We would like to express our sincere gratitude to the PiKVM team for their outstanding contributions to the open-source community.

## License

GLKVM KVMD is released under the [GPL V3](https://github.com/gl-inet/glkvm/blob/main/LICENSE) license. As a derivative project of PiKVM, we are committed to complying with all terms of the GPL V3 license.

## About KVMD

KVMD is the core daemon of GLKVM/PiKVM. This repository contains the configuration and code of KVMD. If you have any questions not directly related to this codebase, please submit them to the [GLKVM](https://github.com/gl-inet/glkvm/issues) repository.

## Firmware Download

If you want to download the latest or previous firmware, please visit: https://dl.gl-inet.com/kvm/rm1/stable

## Synchronize kvmd changes to the device

When you modify the contents of the kvmd folder and want to synchronize it to the kvm device, you can do so by executing the **apply_to_glkvm.sh** script (note: it needs to be in the same LAN as the kvm device). After execution, you need to restart the kvm device.

## FunctionFS mouse mode (USB KVM switch compatibility)

Some USB KVM switches (for example the TESmart HKS-series "dedicated keyboard/mouse" ports) re-emulate the composite HID device towards the host and assign duplicate OUT endpoint addresses to the HID interfaces. Windows then rejects the configuration (Code 10, `SELECT_CONFIGURATION` fails with `USBD_STATUS_INVALID_PARAMETER`) and neither keyboard nor mouse works. The configfs `f_hid` function on the current RM1 kernel (4.19) always creates an interrupt OUT endpoint and does not expose the `no_out_endpoint` attribute that `kvmd-otg` already tries to set.

As a workaround, the mouse interfaces can be served through FunctionFS with interrupt IN endpoints only. The keyboard stays on `hid.usb0` (it needs the OUT endpoint for LED reports and the switch hotkeys). Enable it in `/etc/kvmd/override.yaml` and reboot:

```yaml
otg:
    devices:
        hid:
            ffs_mouse:
                enabled: true
```

What this does:

- `kvmd-otg start` creates an `ffs.mouse` function (absolute mouse plus, if `mouse_alt` is enabled, relative mouse) instead of linking `hid.usb1`/`hid.usb2`, mounts FunctionFS on `/dev/ffs-mouse` and starts a small daemon (`python3 -m kvmd.apps.otg.ffshid`) that answers the HID control requests. The configfs mouse functions are still created but left unlinked so that `/dev/hidgN` numbering of the other HID functions does not change.
- `kvmd.hid.mouse.device` and `kvmd.hid.mouse_alt.device` are pointed at `/dev/ffs-mouse/ep1` and `ep2` automatically.
- `kvmd-otg stop` stops the daemon and unmounts FunctionFS after the gadget is unbound.

Do not enable `hid.usb1`/`hid.usb2` with `kvmd-otgconf` while this mode is active. See the tests in `testenv/tests/apps/otg/test_ffs.py` for the descriptor layout.
