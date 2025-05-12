# GLKVM KVMD

GLKVM KVMD is a derivative project based on the open-source [PiKVM](https://github.com/pikvm/pikvm). We would like to express our sincere gratitude to the PiKVM team for their outstanding contributions to the open-source community.

## License

GLKVM KVMD is released under the [GPL V3](https://github.com/gl-inet/glkvm/blob/main/LICENSE) license. As a derivative project of PiKVM, we are committed to complying with all terms of the GPL V3 license.

## About KVMD

KVMD is the core daemon of GLKVM/PiKVM. This repository contains the configuration and code of KVMD. If you have any questions not directly related to this codebase, please submit them to the [GLKVM](https://github.com/gl-inet/glkvm/issues) repository.

## Synchronize kvmd changes to the device

When you modify the contents of the kvmd folder and want to synchronize it to the kvm device, you can do so by executing the **apply_to_glkvm.sh** script (note: it needs to be in the same LAN as the kvm device). After execution, you need to restart the kvm device.
