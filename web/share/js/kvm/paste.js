/*****************************************************************************
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
*****************************************************************************/


"use strict";


import {tools, $} from "../tools.js";
import {wm} from "../wm.js";


export function Paste(__recorder) {
	var self = this;
	let active = null;
	let paused = false;
	let available = false;
	let pausePending = false;
	let revision = 0;
	const updatePause = function() {
		$("hid-pak-pause-button").textContent = paused ? "Resume typing" : "Pause typing";
		tools.el.setEnabled($("hid-pak-pause-button"), !!active && !pausePending);
	};

	const readSettings = function(showError = false) {
		let speed = 0;
		if ($("hid-pak-custom-switch").checked) {
			speed = Number($("hid-pak-speed").value);
			if (!Number.isInteger(speed) || speed < 1 || speed > 1000) {
				if (showError) wm.error("Enter a typing speed between 1 and 1000 WPM");
				return null;
			}
		}
		return {
			"slow": $("hid-pak-slow-switch").checked,
			"variable": $("hid-pak-variable-switch").checked,
			"super_variable": $("hid-pak-super-variable-switch").checked,
			"speed": speed,
		};
	};

	const updateSettings = function() {
		if (!active) return;
		const settings = readSettings();
		if (!settings) return;
		const id = active;
		tools.httpPost("api/hid/print_pause", {
			"paste_id": id, "revision": ++revision, ...settings,
		}, function(http) {
			if (active === id && http.status !== 200) {
				wm.error("Unable to update typing settings", http.responseText);
			}
		});
	};

	/************************************************************************/

	var __init__ = function() {
		for (const help of document.querySelectorAll(".hid-pak-help")) {
			tools.el.setOnClick(help, function() {
				wm.info(tools.escape(help.title));
			});
		}
		$("hid-pak-text").addEventListener("keyup", function(ev) {
			if (ev.ctrlKey && ev.code == "Enter") {
				$("hid-pak-button").click();
			}
		});

		tools.storage.bindSimpleSwitch($("hid-pak-ask-switch"), "hid.pak.ask", true);
		tools.storage.bindSimpleSwitch($("hid-pak-slow-switch"), "hid.pak.slow", false);
		tools.storage.bindSimpleSwitch($("hid-pak-variable-switch"), "hid.pak.variable", false);
		tools.storage.bindSimpleSwitch($("hid-pak-super-variable-switch"), "hid.pak.super_variable", false);

		tools.storage.bindSimpleSwitch($("hid-pak-custom-switch"), "hid.pak.custom", false, function(value) {
			$("hid-pak-speed-row").hidden = !value;
		});
		$("hid-pak-speed").value = tools.storage.get("hid.pak.speed", "75");
		$("hid-pak-speed").addEventListener("change", function() {
			if ($("hid-pak-speed").checkValidity() && $("hid-pak-speed").value !== "") {
				tools.storage.set("hid.pak.speed", $("hid-pak-speed").value);
			}
			updateSettings();
		});
		for (const name of ["slow", "variable", "super-variable", "custom"]) {
			$("hid-pak-" + name + "-switch").addEventListener("change", updateSettings);
		}
		tools.el.setOnClick($("hid-pak-pause-button"), function() {
			if (!active || pausePending) return;
			const id = active;
			const desired = !paused;
			const params = {"paste_id": id, "paused": desired};
			if (!desired) {
				const settings = readSettings(true);
				if (!settings) return;
				Object.assign(params, settings, {"revision": ++revision});
			}
			pausePending = true;
			updatePause();
			tools.httpPost("api/hid/print_pause", params, function(http) {
				if (active !== id) return;
				pausePending = false;
				if (http.status === 200) paused = desired;
				else wm.error("Unable to change paste pause state", http.responseText);
				updatePause();
			});
		});

		tools.storage.bindSimpleSwitch($("hid-pak-secure-switch"), "hid.pak.secure", false, function(value) {
			$("hid-pak-text").style.setProperty("-webkit-text-security", (value ? "disc" : "none"));
		});

		$("hid-pak-keymap-selector").addEventListener("change", function() {
			tools.storage.set("hid.pak.keymap", $("hid-pak-keymap-selector").value);
		});

		tools.el.setOnClick($("hid-pak-button"), __clickPasteAsKeysButton);
	};

	/************************************************************************/

	self.setState = function(state) {
		available = !!state;
		tools.el.setEnabled($("hid-pak-text"), available && !active);
		tools.el.setEnabled($("hid-pak-button"), available && !active);
		if (state) {
			let el = $("hid-pak-keymap-selector");
			let sel = tools.storage.get("hid.pak.keymap", state.keymaps["default"]);
			el.options.length = 0;
			for (let keymap of state.keymaps.available) {
				tools.selector.addOption(el, keymap, keymap, (keymap === sel));
			}
		}
	};

	var __clickPasteAsKeysButton = function() {
		if (active || !available) return;
		let text = $("hid-pak-text").value;
		if (text) {
			let paste_as_keys = function() {
				if (active || !available) return;
				const settings = readSettings(true);
				if (!settings) return;
				active = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
				paused = false;
				pausePending = false;
				revision = 0;
				updatePause();
				tools.el.setEnabled($("hid-pak-text"), false);
				tools.el.setEnabled($("hid-pak-button"), false);
				tools.el.setEnabled($("hid-pak-keymap-selector"), false);

				let keymap = $("hid-pak-keymap-selector").value;
				const {slow, variable, super_variable, speed} = settings;

				tools.debug(`HID: paste-as-keys ${keymap}: ${text.length} characters`);

				tools.httpPost("api/hid/print", {"limit": 0, "keymap": keymap, ...settings, "paste_id": active}, function(http) {
					active = null;
					paused = false;
					pausePending = false;
					updatePause();
					tools.el.setEnabled($("hid-pak-text"), available);
					tools.el.setEnabled($("hid-pak-button"), available);
					tools.el.setEnabled($("hid-pak-keymap-selector"), true);
					$("hid-pak-text").value = "";
					if (http.status === 413) {
						wm.error("Too many text for paste!");
					} else if (http.status !== 200) {
						wm.error("HID paste error", http.responseText);
					} else if (http.status === 200) {
						__recorder.recordPrintEvent(text, keymap, slow, variable, super_variable, speed);
					}
				}, text, "text/plain", 7 * 24 * 3600 * 1000);
			};

			if ($("hid-pak-ask-switch").checked) {
				wm.confirm(`
					You're going to paste ${text.length} character${text.length !== 1 ? "s" : ""}.<br>
					Are you sure you want to continue?
				`).then(function(ok) {
					if (ok) {
						paste_as_keys();
					} else {
						$("hid-pak-text").value = "";
					}
				});
			} else {
				paste_as_keys();
			}
		}
	};

	__init__();
}
