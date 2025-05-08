#!/bin/sh

LOCAL_DIR="kvmd"
REMOTE_HOST="glkvm.local"
REMOTE_DIR="/usr/lib/python3.12/site-packages/kvmd"
REMOTE_USER="root"
SSH_PORT=22

if [ ! -d "$LOCAL_DIR" ]; then
	echo "Error: '$LOCAL_DIR' does not exist."
	exit 1
fi

if ! command -v scp &> /dev/null || ! command -v ssh &> /dev/null; then
	echo "Error: Please install OpenSSH client"
	exit 1
fi

transfer_files() {
	scp -r -P "$SSH_PORT" "$LOCAL_DIR"/* "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

	if [ $? -eq 0 ]; then
		echo "OK! Please restart the kvm device to make the configuration take effect."
	else
		echo "Failed!"
		exit 1
	fi
}

echo "LOCAL DIR: $LOCAL_DIR"
echo "REMOTE TARGET: $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR"

echo "Clear the target environment ..."
ssh "$REMOTE_USER@$REMOTE_HOST" "rm $REMOTE_DIR/* -R"

transfer_files
