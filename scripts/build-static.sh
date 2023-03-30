#!/bin/sh

GARM_SOURCE="/build/garm-provider-azure"
BIN_DIR="$GARM_SOURCE/bin"
git config --global --add safe.directory "$GARM_SOURCE"

[ ! -d "$BIN_DIR" ] && mkdir -p "$BIN_DIR"

export CGO_ENABLED=1
USER_ID=${USER_ID:-$UID}
USER_GROUP=${USER_GROUP:-$(id -g)}

cd $GARM_SOURCE
go build -mod vendor -o $BIN_DIR/garm-provider-azure -tags osusergo,netgo -ldflags "-linkmode external -extldflags '-static' -s -w" .

chown $USER_ID:$USER_GROUP -R "$BIN_DIR"
