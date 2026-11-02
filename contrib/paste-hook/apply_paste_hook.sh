#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install, remove or inspect the GLKVM paste hook on a device over SSH.
#
#   apply_paste_hook.sh install|remove|status
#
# Environment: GLKVM_HOST (default glkvm.local), GLKVM_PORT (default 22).
# Password authentication is left entirely to ssh/scp; one SSH connection is
# shared between steps so you are normally asked for the password only once.

set -eu

REMOTE_HOST="${GLKVM_HOST:-glkvm.local}"
REMOTE_USER="root"
SSH_PORT="${GLKVM_PORT:-22}"
TARGET="$REMOTE_USER@$REMOTE_HOST"

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LOCAL_JS="$SCRIPT_DIR/paste-hook.js"
LOCAL_HOOK="$SCRIPT_DIR/S90paste-hook.sh"

REMOTE_JS_DIR="/etc/kvmd/user/paste-hook"
REMOTE_JS="$REMOTE_JS_DIR/paste-hook.js"
REMOTE_SCRIPTS_DIR="/etc/kvmd/user/scripts"
REMOTE_HOOK="$REMOTE_SCRIPTS_DIR/S90paste-hook.sh"
WEB_IDX="/usr/share/kvmd/glweb/index.html"
WEB_JS="/usr/share/kvmd/glweb/paste-hook.js"
ROM_IDX="/rom/usr/share/kvmd/glweb/index.html"

usage() {
	echo "Usage: $0 install|remove|status"
	echo "  GLKVM_HOST=$REMOTE_HOST GLKVM_PORT=$SSH_PORT"
	exit 2
}

if ! command -v scp >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
	echo "Error: Please install OpenSSH client"
	exit 1
fi

# Shared SSH connection: one password prompt for all steps.
CONTROL_PATH="/tmp/paste-hook-ssh-$$"
SSH_OPTS="-o ControlMaster=auto -o ControlPath=$CONTROL_PATH -o ControlPersist=60"

cleanup() {
	# shellcheck disable=SC2086
	ssh $SSH_OPTS -p "$SSH_PORT" -O exit "$TARGET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

remote() {
	# shellcheck disable=SC2086
	ssh $SSH_OPTS -p "$SSH_PORT" "$TARGET" "$@"
}

do_install() {
	for f in "$LOCAL_JS" "$LOCAL_HOOK"; do
		if [ ! -f "$f" ]; then
			echo "Error: '$f' does not exist."
			exit 1
		fi
	done

	echo "Uploading to $TARGET:/tmp/ ..."
	# shellcheck disable=SC2086
	if ! scp $SSH_OPTS -P "$SSH_PORT" "$LOCAL_JS" "$LOCAL_HOOK" "$TARGET:/tmp/"; then
		echo "Failed!"
		exit 1
	fi

	echo "Installing and activating ..."
	if remote "
		set -e
		mkdir -p $REMOTE_JS_DIR $REMOTE_SCRIPTS_DIR
		mv -f /tmp/paste-hook.js $REMOTE_JS
		mv -f /tmp/S90paste-hook.sh $REMOTE_HOOK
		chmod 644 $REMOTE_JS
		chmod 755 $REMOTE_HOOK
		sh $REMOTE_HOOK start
		n=\$(grep -c paste-hook $WEB_IDX || true)
		echo \"grep -c paste-hook $WEB_IDX: \$n\"
		ls -l $WEB_JS
		[ \"\$n\" = 1 ]
	"; then
		echo "OK! Hard-reload the KVM web UI (Cmd+Shift+R / Ctrl+Shift+R, or restart the GLKVM app). No reboot needed."
	else
		echo "Failed! The hook did not activate; see the messages above."
		exit 1
	fi
}

do_remove() {
	if [ ! -f "$LOCAL_HOOK" ]; then
		echo "Error: '$LOCAL_HOOK' does not exist."
		exit 1
	fi
	# The local hook copy is piped on stdin and used only if the device
	# copy is already gone, so leftover overlay files are still cleaned up.
	if remote "
		if [ -f $REMOTE_HOOK ]; then sh $REMOTE_HOOK remove; else sh -s remove; fi
		rm -f $REMOTE_JS $REMOTE_HOOK
		rmdir $REMOTE_JS_DIR 2>/dev/null || true
		if diff -q $ROM_IDX $WEB_IDX; then
			echo 'index.html is identical to the firmware original.'
		else
			echo 'WARNING: index.html differs from the firmware original.'
			exit 1
		fi
	" < "$LOCAL_HOOK"; then
		echo "OK! Paste hook removed. Hard-reload the KVM web UI."
	else
		echo "Failed!"
		exit 1
	fi
}

do_status() {
	remote "
		for f in $REMOTE_JS $REMOTE_HOOK $WEB_JS; do
			if [ -e \$f ]; then ls -l \$f; else echo \"missing: \$f\"; fi
		done
		n=\$(grep -c paste-hook.js $WEB_IDX 2>/dev/null || true)
		echo \"index.html marker count: \${n:-0}\"
		if diff -q $ROM_IDX $WEB_IDX >/dev/null 2>&1; then
			echo 'index.html: firmware original'
		else
			echo 'index.html: differs from firmware original (patched)'
		fi
	"
}

echo "REMOTE TARGET: $TARGET (port $SSH_PORT)"

case "${1:-}" in
	install) do_install ;;
	remove) do_remove ;;
	status) do_status ;;
	*) usage ;;
esac
