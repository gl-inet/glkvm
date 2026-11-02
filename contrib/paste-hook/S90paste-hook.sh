# SPDX-License-Identifier: GPL-3.0-or-later
#
# S90paste-hook.sh - GLKVM boot hook that injects paste-hook.js into the web UI.
#
# Installed as /etc/kvmd/user/scripts/S90paste-hook.sh. /etc/init.d/S99custom
# *sources* it in a subshell with $1=start at boot and $1=stop at shutdown.
# It can also be run directly: sh S90paste-hook.sh start|stop|remove
#
# Because it may be sourced: no top-level exit, functions only, all names
# prefixed ph_. POSIX sh / BusyBox ash only.
#
# On every start, index.html is regenerated from the read-only firmware copy
# under /rom, so a firmware upgrade never ends up shadowed by a stale patched
# copy. If /rom does not look as expected, the hook removes its overlay files
# and does nothing else.

ph_SRC_JS=/etc/kvmd/user/paste-hook/paste-hook.js
ph_WEB=/usr/share/kvmd/glweb
ph_ROM_WEB=/rom/usr/share/kvmd/glweb
ph_JS_DST=$ph_WEB/paste-hook.js
ph_IDX=$ph_WEB/index.html
ph_ROM_IDX=$ph_ROM_WEB/index.html
ph_MARK=paste-hook.js
# Writable overlayfs upper layer (deleting there re-exposes the /rom file
# without leaving a whiteout behind).
ph_UPPER=/userdata/overlay/upper

ph_log() {
	if command -v logger >/dev/null 2>&1; then
		logger -t paste-hook "$*"
	fi
	echo "paste-hook: $*"
}

# Print the first 8 hex chars of a checksum of $1 (sha256sum, else md5sum).
ph_hash() {
	ph_h=""
	if command -v sha256sum >/dev/null 2>&1; then
		ph_h=$(sha256sum "$1" 2>/dev/null)
	elif command -v md5sum >/dev/null 2>&1; then
		ph_h=$(md5sum "$1" 2>/dev/null)
	fi
	ph_h=${ph_h%% *}
	if [ ${#ph_h} -ge 8 ]; then
		ph_h=${ph_h%"${ph_h#????????}"}
	else
		ph_h=0
	fi
	printf '%s' "$ph_h"
}

ph_idx_is_ours() {
	[ -f "$ph_IDX" ] && grep -q "$ph_MARK" "$ph_IDX" 2>/dev/null
}

ph_remove_overlay() {
	rm -f "$ph_JS_DST" 2>/dev/null
	rm -f "$ph_WEB"/.index.html.paste-hook.* 2>/dev/null

	if ! ph_idx_is_ours; then
		return 0
	fi

	# Prefer deleting the copy in the upper layer: this exposes the /rom
	# original. Deleting through the merged view would leave a whiteout
	# (hiding the original) on a standard overlayfs.
	if [ -e "$ph_UPPER$ph_IDX" ]; then
		rm -f "$ph_UPPER$ph_IDX" 2>/dev/null
		# Make the merged view notice the change in the upper layer.
		sync 2>/dev/null
		echo 2 > /proc/sys/vm/drop_caches 2>/dev/null
	else
		rm -f "$ph_IDX" 2>/dev/null
	fi

	# Last resort: never leave the UI without a usable index.html.
	if [ -f "$ph_ROM_IDX" ] && { [ ! -f "$ph_IDX" ] || ph_idx_is_ours; }; then
		ph_log "overlay index.html still present or missing; restoring a copy of the firmware original"
		if cp -f "$ph_ROM_IDX" "$ph_IDX.paste-hook.tmp" 2>/dev/null; then
			mv -f "$ph_IDX.paste-hook.tmp" "$ph_IDX" 2>/dev/null
		fi
	fi
	ph_log "removed overlay files"
	return 0
}

ph_start() {
	if [ ! -f "$ph_SRC_JS" ]; then
		ph_log "missing $ph_SRC_JS; disabling"
		ph_remove_overlay
		return 0
	fi
	if [ ! -f "$ph_ROM_IDX" ]; then
		ph_log "missing $ph_ROM_IDX; disabling"
		ph_remove_overlay
		return 0
	fi
	if ! grep -q '</head>' "$ph_ROM_IDX" 2>/dev/null; then
		ph_log "no </head> in $ph_ROM_IDX (firmware layout changed?); disabling"
		ph_remove_overlay
		return 0
	fi
	if grep -q "$ph_MARK" "$ph_ROM_IDX" 2>/dev/null; then
		ph_log "firmware index.html already references $ph_MARK; disabling"
		ph_remove_overlay
		return 0
	fi

	if ! cp -f "$ph_SRC_JS" "$ph_JS_DST" 2>/dev/null; then
		ph_log "cannot copy $ph_SRC_JS to $ph_JS_DST; disabling"
		ph_remove_overlay
		return 0
	fi

	chmod 644 "$ph_JS_DST" 2>/dev/null
	ph_v=$(ph_hash "$ph_JS_DST")
	ph_tmp="$ph_WEB/.index.html.paste-hook.$$"

	# Always derive from the pristine /rom copy, never from the current file.
	if ! sed "s|</head>|<script src=\"./paste-hook.js?v=$ph_v\"></script></head>|" \
		"$ph_ROM_IDX" > "$ph_tmp" 2>/dev/null; then
		rm -f "$ph_tmp" 2>/dev/null
		ph_log "sed failed; disabling"
		ph_remove_overlay
		return 0
	fi
	chmod 644 "$ph_tmp" 2>/dev/null
	if ! mv -f "$ph_tmp" "$ph_IDX" 2>/dev/null; then
		rm -f "$ph_tmp" 2>/dev/null
		ph_log "cannot write $ph_IDX; disabling"
		ph_remove_overlay
		return 0
	fi

	ph_n=$(grep -c "$ph_MARK" "$ph_IDX" 2>/dev/null)
	if [ "$ph_n" != "1" ]; then
		ph_log "verification failed (marker count '$ph_n'); disabling"
		ph_remove_overlay
		return 0
	fi
	ph_log "injected paste-hook.js?v=$ph_v into $ph_IDX"
	return 0
}

case "${1:-}" in
	start)
		ph_start
		;;
	stop)
		:
		;;
	remove)
		ph_remove_overlay
		;;
	*)
		echo "usage: S90paste-hook.sh start|stop|remove"
		;;
esac
