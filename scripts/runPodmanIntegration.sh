#!/usr/bin/env bash
# Own the native fixture for the lifetime of the supplied validation command.
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo 'Usage: bash scripts/runPodmanIntegration.sh <validation command> [arguments...]' >&2
  exit 2
fi
if [[ $(uname -s) != Linux ]]; then
  echo 'The native Podman CI fixture requires Ubuntu 24.04.' >&2
  exit 1
fi
# shellcheck source=/dev/null
source /etc/os-release
if [[ $ID != ubuntu || $VERSION_ID != 24.04 ]]; then
  echo 'The native Podman CI fixture requires Ubuntu 24.04.' >&2
  exit 1
fi

readonly podman_package_version='4.9.3+ds1-1ubuntu0.2'
readonly helper_image='docker.io/library/python@sha256:db3231d3fce4c59182f8364dbec08b8bad4fdfca673dfb226f3c9e77b6b48cd2'
if [[ $(dpkg-query -W -f='${Version}' podman 2>/dev/null) != "$podman_package_version" ]] || \
  [[ ! -x /usr/sbin/sshd ]] || ! command -v openssl >/dev/null; then
  sudo -n apt-get update
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    "podman=$podman_package_version" openssh-server openssl sudo
fi
[[ $(dpkg-query -W -f='${Version}' podman) == "$podman_package_version" ]]
[[ $(sudo -n podman --version) == 'podman version 4.9.3' ]]
sudo -n podman pull "$helper_image"

umask 077
fixture_directory=$(mktemp -d /tmp/paratix-podman-ci.XXXXXXXX)
readonly fixture_directory
fixture_id=${fixture_directory##*.}
readonly fixture_user="paratix-podman-$fixture_id"
readonly fixture_unit="paratix-podman-$fixture_id.service"
readonly test_root="/var/lib/paratix-integration-$fixture_id"
readonly sudoers_file="/etc/sudoers.d/paratix-podman-$fixture_id"
user_created=false
service_started=false
sudoers_created=false
test_root_created=false
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  set +e
  if [[ $service_started == true ]]; then
    sudo -n systemctl stop "$fixture_unit" || result=1
  fi
  if [[ $sudoers_created == true ]]; then
    sudo -n rm -f -- "$sudoers_file" || result=1
  fi
  if [[ $user_created == true ]]; then
    sudo -n userdel --remove "$fixture_user" || result=1
  fi
  if [[ $test_root_created == true ]]; then
    sudo -n rm -rf -- "$test_root" || result=1
  fi
  sudo -n rm -rf -- "$fixture_directory" || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo -n test ! -e "$sudoers_file"
sudo -n test ! -e "$test_root"
sudo -n useradd --create-home --shell /bin/bash --password '*' "$fixture_user"
user_created=true
printf '%s ALL=(root) NOPASSWD: ALL\n' "$fixture_user" > "$fixture_directory/sudoers"
sudo -n visudo -cf "$fixture_directory/sudoers"
sudo -n install -o root -g root -m 0440 "$fixture_directory/sudoers" "$sudoers_file"
sudoers_created=true
sudo -n install -d -o root -g root -m 0700 "$test_root"
test_root_created=true
sudo -n install -d -o root -g root -m 0755 /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$fixture_directory/client_key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture_directory/host_key"
sudo -n install -d -o "$fixture_user" -g "$fixture_user" -m 0700 "/home/$fixture_user/.ssh"
sudo -n install -o "$fixture_user" -g "$fixture_user" -m 0600 \
  "$fixture_directory/client_key.pub" "/home/$fixture_user/.ssh/authorized_keys"

# Reserve an ephemeral loopback port for selection; sshd must bind it successfully.
fixture_port=$(node --input-type=module -e '
  import { createServer } from "node:net";
  const server = createServer();
  server.listen(0, "127.0.0.1", () => {
    console.log(server.address().port);
    server.close();
  });
')
[[ $fixture_port =~ ^[0-9]+$ ]]
cat > "$fixture_directory/sshd_config" <<EOF_SSHD
ListenAddress 127.0.0.1
Port $fixture_port
HostKey $fixture_directory/host_key
PidFile $fixture_directory/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers $fixture_user
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
UsePAM no
StrictModes yes
AllowTcpForwarding remote
PermitListen 127.0.0.1:*
GatewayPorts no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
LogLevel ERROR
EOF_SSHD
sudo -n /usr/sbin/sshd -t -f "$fixture_directory/sshd_config"
# A transient service keeps all SSH children within an owned cleanup boundary.
sudo -n systemd-run --quiet --unit="$fixture_unit" --property=KillMode=control-group \
  /usr/sbin/sshd -D -e -f "$fixture_directory/sshd_config"
service_started=true

ssh_options=(
  -F /dev/null -i "$fixture_directory/client_key" -p "$fixture_port"
  -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=2
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$fixture_directory/known_hosts"
)
printf '[127.0.0.1]:%s %s\n' "$fixture_port" "$(cut -d ' ' -f 1,2 "$fixture_directory/host_key.pub")" \
  > "$fixture_directory/known_hosts"
ready=false
for ((attempt = 0; attempt < 30; attempt++)); do
  if ssh "${ssh_options[@]}" "$fixture_user@127.0.0.1" 'test "$(id -u)" != 0 && test "$(sudo -n id -u)" = 0' 2>/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [[ $ready != true ]]; then
  echo 'Native Podman SSH/root preflight failed.' >&2
  sudo -n journalctl --unit="$fixture_unit" --no-pager -n 20 >&2
  exit 1
fi
[[ $(ssh "${ssh_options[@]}" "$fixture_user@127.0.0.1" 'sudo -n podman --version') == 'podman version 4.9.3' ]]
# Exercise the real rootful helper with the same restrictions as the module.
# The image is a trusted constant, expanded on the controller.
# shellcheck disable=SC2029
ssh "${ssh_options[@]}" "$fixture_user@127.0.0.1" \
  "sudo -n podman run --rm --pull=never --user 0:0 --userns=host --network=none --read-only --read-only-tmpfs=false --cap-drop=all --security-opt=no-new-privileges --log-driver=none --entrypoint python3 $helper_image -I -B -c 'import sys; assert sys.version_info[:3] == (3,15,0)'"

export PARATIX_PODMAN_HOST=127.0.0.1
export PARATIX_PODMAN_PORT="$fixture_port"
export PARATIX_PODMAN_USER="$fixture_user"
export PARATIX_PODMAN_PRIVATE_KEY="$fixture_directory/client_key"
PARATIX_PODMAN_HOST_PUBLIC_KEY=$(cut -d ' ' -f 1,2 "$fixture_directory/host_key.pub")
export PARATIX_PODMAN_HOST_PUBLIC_KEY
export PARATIX_PODMAN_EXPECTED_VERSION=4.9.3
export PARATIX_PODMAN_TEST_ROOT="$test_root"
"$@"
