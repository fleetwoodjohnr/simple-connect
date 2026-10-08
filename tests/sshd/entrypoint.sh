#!/bin/sh
# Host keys are generated per container start unless mounted, so the changed-key
# test can simply recreate the container. AUTHORIZED_KEY seeds user "key".
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
if [ -n "$AUTHORIZED_KEY" ]; then
  echo "$AUTHORIZED_KEY" > /home/key/.ssh/authorized_keys
  chown -R key:key /home/key/.ssh && chmod 600 /home/key/.ssh/authorized_keys
fi
exec /usr/sbin/sshd -D -e
