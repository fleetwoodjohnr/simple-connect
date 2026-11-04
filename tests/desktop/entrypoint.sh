#!/bin/sh
# Starts sshd plus the desktops described in the Containerfile.
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
if [ -n "$AUTHORIZED_KEY" ]; then
  echo "$AUTHORIZED_KEY" > /home/key/.ssh/authorized_keys
  chown -R key:key /home/key/.ssh && chmod 600 /home/key/.ssh/authorized_keys
fi
uid=$(id -u pw)
mkdir -p /run/user/$uid && chown pw:pw /run/user/$uid && chmod 700 /run/user/$uid
mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix

# A logged-in X11 desktop on :0, as if pw sat at the machine.
su pw -s /bin/sh -c '
  cookie=$(od -An -N16 -tx1 /dev/urandom | tr -d " \n")
  xauth -q -f "$HOME/.Xauthority" add :0 . "$cookie"
  Xvfb :0 -screen 0 1024x768x24 -auth "$HOME/.Xauthority" -nolisten tcp >/tmp/xvfb.log 2>&1 &
  sleep 1
  export DISPLAY=:0 XAUTHORITY="$HOME/.Xauthority"
  xsetroot -solid "#2a6f4a"
  openbox >/dev/null 2>&1 &
  xterm -geometry 80x24+40+40 >/dev/null 2>&1 &
'
# A headless wlroots session (wayvnc can share it).
su pw -s /bin/sh -c "
  XDG_RUNTIME_DIR=/run/user/$uid WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1 \
    /usr/local/bin/sway -c /etc/sway/test.conf >/tmp/sway.log 2>&1 &
"
# Virtual desktops start openbox with an xterm (xrdp sessions start a plain xterm).
mkdir -p /home/pw/.config/openbox
echo 'xterm -geometry 80x24+40+40 &' > /home/pw/.config/openbox/autostart
chown -R pw:pw /home/pw/.config

# xrdp on loopback only.
[ -f /etc/xrdp/key.pem ] || (cd /etc/xrdp && xrdp-keygen xrdp auto >/dev/null 2>&1 || true)
xrdp-sesman >/tmp/sesman.log 2>&1 || true
xrdp >/tmp/xrdp.log 2>&1 || true

exec /usr/sbin/sshd -D -e
