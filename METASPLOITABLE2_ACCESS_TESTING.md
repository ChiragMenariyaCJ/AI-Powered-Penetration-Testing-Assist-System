# PTAS Restricted Metasploitable 2 Access-Testing Setup

This guide configures the only platform currently accepted by PTAS
`ACCESS_TESTING`: a locally registered Metasploitable 2 VM in VirtualBox.

Metasploitable 2 is intentionally vulnerable. Never bridge it, expose it to a
physical network, forward its ports, or give it a NAT adapter. Rapid7 describes
it as an intentionally vulnerable Ubuntu VM for testing common vulnerabilities
and recommends an isolated test environment:

- [Rapid7 Metasploitable 2 setup](https://docs.rapid7.com/metasploit/metasploitable-2/)
- [Rapid7 Metasploitable 2 exploitability guide](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/)

## 1. What PTAS permits

The first access-testing implementation provides one-at-a-time, manually
executed, credential-based exercises for detected services:

- SSH training login
- FTP training login
- Telnet training login
- SMB share listing
- MySQL authentication
- PostgreSQL authentication

PTAS does not execute these commands. It does not store passwords. It does not
provide arbitrary exploit modules, payloads, brute force, persistence, or
privilege escalation.

Before showing an exercise, PTAS verifies:

1. The manifest profile is exactly `metasploitable2`.
2. The target is one private IP, not loopback, public, or a CIDR.
3. The registered VirtualBox UUID still exists.
4. Every enabled VM network adapter is host-only.
5. The registered host-only MAC still matches the VM.
6. The VM is running.
7. At least one VirtualBox snapshot exists.
8. The target IP resolves to the registered VM MAC.
9. The completed scan target equals the registered IP.
10. The scan contains a sufficiently distinctive Metasploitable 2 service/port fingerprint.
11. The student types `ENABLE ACCESS TESTING` for the current request.

## 2. Install VirtualBox on Kali

The current Kali package repository provides VirtualBox. Install it and the
matching kernel headers:

```bash
sudo apt update
sudo apt install -y virtualbox linux-headers-$(uname -r)
```

Verify the command used by PTAS:

```bash
VBoxManage --version
```

Reboot if the kernel modules were installed or upgraded and VirtualBox cannot
start a VM.

## 3. Download and import Metasploitable 2

Download Metasploitable 2 only from the location linked by Rapid7's official
documentation. Extract it into a directory that is not shared publicly.

The simplest import process uses the VirtualBox interface:

1. Open VirtualBox.
2. Create a new Linux/Ubuntu 32-bit VM named `Metasploitable2`.
3. Allocate approximately 1 GB RAM and one CPU.
4. Choose **Use an existing virtual hard disk**.
5. Select the extracted Metasploitable `.vmdk` disk.
6. Do not start it until networking is isolated.

## 4. Configure host-only networking

In VirtualBox:

1. Open **Tools → Network → Host-only Networks**.
2. Create a host-only network, commonly `vboxnet0`.
3. Configure the host address, for example `192.168.56.1/24`.
4. Open **Metasploitable2 → Settings → Network**.
5. Enable only **Adapter 1**.
6. Set **Attached to** to **Host-only Adapter**.
7. Select `vboxnet0`.
8. Disable adapters 2–4.

Confirm through the terminal:

```bash
VBoxManage showvminfo Metasploitable2 --machinereadable | \
  grep -E '^(UUID|VMState|nic[0-9]+|macaddress[0-9]+|hostonlyadapter[0-9]+)='
```

The enabled `nic` value must be `hostonly`. PTAS refuses `nat`, `bridged`,
`intnet`, or other enabled network modes.

## 5. Start the VM and find its private IP

Start the VM:

```bash
VBoxManage startvm Metasploitable2 --type gui
```

The documented Metasploitable 2 training login is commonly:

```text
username: msfadmin
password: msfadmin
```

Inside the VM, display its address:

```bash
ifconfig
```

This guide uses `192.168.56.101` as an example. Substitute the actual host-only
IP in every command.

From Kali, establish the neighbor entry and verify connectivity:

```bash
ping -c 1 192.168.56.101
ip neigh show 192.168.56.101
```

Do not proceed if the address appears on a physical, bridged, NAT, VPN, or
internet-facing interface.

## 6. Create a clean snapshot

After confirming the VM starts correctly, create the required baseline:

```bash
VBoxManage snapshot Metasploitable2 take clean-baseline \
  --description "Clean PTAS training baseline"
```

Verify it:

```bash
VBoxManage snapshot Metasploitable2 list --details
```

## 7. Register the VM with PTAS

From the PTAS repository root:

```bash
./ptas.sh lab-register \
  --name msf2-local \
  --target 192.168.56.101 \
  --vm Metasploitable2
```

PTAS reads the VM UUID and host-only MAC directly from VirtualBox and stores a
local manifest at:

```text
.ptas/labs/msf2-local.json
```

The `.ptas/` directory is excluded from version control.

## 8. Verify the registered lab

Make sure the VM is running and its neighbor entry exists, then run:

```bash
ping -c 1 192.168.56.101
./ptas.sh lab-check --name msf2-local
```

Do not continue until PTAS reports that UUID, network, snapshot, and MAC checks
all pass.

## 9. Scan the registered target

Start the normal two-pane workflow:

```bash
./ptas.sh start
```

Use an exact scope and target:

```text
Authorized scope: 192.168.56.101
Training target inside that scope: 192.168.56.101
```

Enable CVE correlation if wanted. Allow all scan stages and service-aware checks
to finish. PTAS prints the final scan ID in the recommendation and report
commands. Use that final ID—not an earlier Quick or Full stage ID.

## 10. Request the first access exercise

If the final scan ID is `42`:

```bash
./ptas.sh access-test \
  --scan-id 42 \
  --lab msf2-local
```

PTAS repeats all identity and isolation checks. Type this exact confirmation:

```text
ENABLE ACCESS TESTING
```

PTAS then shows one allowlisted exercise and its command. Review it and execute
it manually only against the displayed registered IP. Password prompts remain
interactive and are not captured by PTAS state.

Request the next exercise:

```bash
./ptas.sh access-test --scan-id 42 --lab msf2-local
```

Restart the exercise sequence:

```bash
./ptas.sh access-test --scan-id 42 --lab msf2-local --reset
```

Presentation progress is stored locally in:

```text
.ptas/access-state.json
```

## 11. Generate JSON and HTML reports

```bash
./ptas.sh report \
  --scan-id 42 \
  --output reports/ptas-scan-42.json
```

This creates:

```text
reports/ptas-scan-42.json
reports/ptas-scan-42.html
```

Access exercises that were presented are recorded as pending recommendations;
presentation does not mean that access succeeded. Record actual evidence before
claiming `AUTHORIZED_ACCESS_CONFIRMED`.

## 12. Restore the clean snapshot

Close any student connections. Then power off and restore the lab through the
VirtualBox interface, or use:

```bash
VBoxManage controlvm Metasploitable2 poweroff
VBoxManage snapshot Metasploitable2 restore clean-baseline
VBoxManage startvm Metasploitable2 --type gui
```

Powering off discards the VM's current running state. Save any authorized
assessment evidence outside the VM before restoration.

## Troubleshooting

### `VBoxManage is not installed`

```bash
sudo apt install -y virtualbox linux-headers-$(uname -r)
```

### Non-host-only adapter error

Disable every NAT, bridged, internal-network, or other adapter in the VM
settings. Leave one host-only adapter enabled and register again.

### No neighbor MAC found

Verify that the VM is running and use its host-only IP:

```bash
ping -c 1 192.168.56.101
ip neigh show 192.168.56.101
```

### Snapshot required

```bash
VBoxManage snapshot Metasploitable2 take clean-baseline
```

### Scan fingerprint rejected

Confirm that the scan ID belongs to the final scan of the registered VM. PTAS
requires several expected ports and at least two distinctive Metasploitable 2
services. It deliberately rejects generic hosts that happen to expose one or
two similar ports.

### Target mismatch

The scan target, manifest target, and current neighbor IP must be identical.
Access testing does not accept domain names, loopback, public addresses, or
network ranges.
