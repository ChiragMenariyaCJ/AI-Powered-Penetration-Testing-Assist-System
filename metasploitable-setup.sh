#!/bin/bash

set -euo pipefail

# Register a Metasploitable 2 VMware guest by IP from inside the Kali guest.
# Rerunning this script with the same lab name safely replaces the old IP/MAC
# registration when VMware DHCP assigns a different address.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
TARGET_IP="${PTAS_METASPLOITABLE_IP:-192.168.121.130}"
LAB_NAME="${PTAS_METASPLOITABLE_LAB:-msf2-local}"
SCAN_ID=""

# Print command usage, supported options, and examples without changing project state.
show_help() {
    cat <<'HELP'
Usage:
  ./metasploitable-setup.sh --target IP [--name LAB] [--scan-id ID]

Examples:
  ./metasploitable-setup.sh --target 192.168.121.130
  ./metasploitable-setup.sh --target 192.168.56.101 --name classroom-msf2
  ./metasploitable-setup.sh --target 192.168.121.130 --scan-id 33

Options:
  --target IP     Current private IP of the Metasploitable 2 guest.
  --name LAB      Saved PTAS lab name (default: msf2-local).
  --scan-id ID    After registration, open the access-test gate for this scan.
  -h, --help      Show this help.

The target can also be supplied through PTAS_METASPLOITABLE_IP and the name
through PTAS_METASPLOITABLE_LAB.
HELP
}

# Parse explicit arguments after loading optional environment defaults.
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "$#" -ge 2 ] || { echo "--target requires an IP." >&2; exit 2; }
            TARGET_IP="$2"
            shift 2
            ;;
        --name)
            [ "$#" -ge 2 ] || { echo "--name requires a lab name." >&2; exit 2; }
            LAB_NAME="$2"
            shift 2
            ;;
        --scan-id)
            [ "$#" -ge 2 ] || { echo "--scan-id requires a number." >&2; exit 2; }
            SCAN_ID="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help >&2
            exit 2
            ;;
    esac
done

# Validate values before using them in paths, commands, or the .env file.
if [ -z "$TARGET_IP" ]; then
    echo "Provide the current Metasploitable IP with --target IP." >&2
    exit 2
fi
if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "--target must be one IPv4 address, for example 192.168.121.130." >&2
    exit 2
fi
if [[ ! "$LAB_NAME" =~ ^[A-Za-z0-9_-]{1,50}$ ]]; then
    echo "Lab name may contain only letters, numbers, underscores, and hyphens." >&2
    exit 2
fi
if [ -n "$SCAN_ID" ] && { [[ ! "$SCAN_ID" =~ ^[0-9]+$ ]] || [ "$SCAN_ID" -le 0 ]; }; then
    echo "--scan-id must be a positive integer." >&2
    exit 2
fi

cd "$PROJECT_DIR"
if [ ! -x "$PROJECT_DIR/ptas.sh" ]; then
    echo "PTAS launcher is missing or not executable: $PROJECT_DIR/ptas.sh" >&2
    exit 1
fi
if [ ! -x "$PROJECT_DIR/.venv/bin/python" ]; then
    echo "PTAS is not installed yet. Run ./kali-setup.sh first." >&2
    exit 1
fi

# Ping populates Kali's neighbor table so PTAS can pin the exact VMware MAC.
# This step does not scan or change anything on the target.
echo "[PTAS] Checking Metasploitable connectivity at $TARGET_IP..."
if ! ping -c 1 -W 3 -- "$TARGET_IP" >/dev/null 2>&1; then
    echo "Could not reach $TARGET_IP. Start the VM and check its host-only IP." >&2
    exit 1
fi

MANIFEST="$PROJECT_DIR/.ptas/labs/$LAB_NAME.json"
if [ -f "$MANIFEST" ]; then
    echo "[PTAS] Updating existing lab '$LAB_NAME' for IP $TARGET_IP."
else
    echo "[PTAS] Creating lab '$LAB_NAME' for $TARGET_IP."
fi

# vmware-network is designed for Kali and Metasploitable running as separate
# guests. It does not require the physical host's inaccessible .vmx path.
"$PROJECT_DIR/ptas.sh" lab-register \
    --name "$LAB_NAME" \
    --provider vmware-network \
    --target "$TARGET_IP"
"$PROJECT_DIR/ptas.sh" lab-check --name "$LAB_NAME"

# Store only the non-secret lab selection. Rerunning with another IP updates
# both these values and the manifest while preserving unrelated .env settings.
if [ ! -f .env ]; then
    cp .env.example .env
fi
# Update one non-secret .env value while preserving every unrelated student setting.
set_env_value() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        printf '\n%s=%s\n' "$key" "$value" >> .env
    fi
}
set_env_value "PTAS_METASPLOITABLE_IP" "$TARGET_IP"
set_env_value "PTAS_METASPLOITABLE_LAB" "$LAB_NAME"

echo "[PTAS] Metasploitable registration is ready."
echo "[PTAS] Lab: $LAB_NAME"
echo "[PTAS] Target: $TARGET_IP"

# A scan ID is optional because a new installation may not have scanned yet.
if [ -n "$SCAN_ID" ]; then
    "$PROJECT_DIR/ptas.sh" access-test --scan-id "$SCAN_ID" --lab "$LAB_NAME"
else
    echo "[PTAS] After scanning, run:"
    echo "  ./ptas.sh access-test --scan-id SCAN_ID --lab $LAB_NAME"
fi
