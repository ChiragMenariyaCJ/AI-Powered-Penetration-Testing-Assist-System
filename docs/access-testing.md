# PTAS Restricted Metasploitable 2 Access-Testing Setup

This guide configures the only target currently accepted by PTAS
`ACCESS_TESTING`: a locally registered Metasploitable 2 VM on an isolated
host-only network. VirtualBox and VMware Workstation/Player are supported.

When Kali and Metasploitable are separate VMware guests, use
`./metasploitable-setup.sh --target TARGET_IP`.

When PTAS itself runs inside a Kali VMware guest, the physical host's `.vmx`
file is normally unavailable inside Kali. Use the `vmware-network` provider in
that topology. It registers the Metasploitable IP, Kali's isolated non-default
route, Kali source address, and the observed VMware MAC instead of requiring a
host filesystem path.

Metasploitable 2 is intentionally vulnerable. Never bridge it, expose it to a
physical network, forward its ports, or give it a NAT adapter. Rapid7 describes
it as an intentionally vulnerable Ubuntu VM for testing common vulnerabilities
and recommends an isolated test environment:

- [Rapid7 Metasploitable 2 setup](https://docs.rapid7.com/metasploit/metasploitable-2/)
- [Rapid7 Metasploitable 2 exploitability guide](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/)

## 1. What PTAS permits

The access-testing implementation provides one-at-a-time, manually
executed, credential-based exercises for detected services:

- SSH training login
- FTP training login
- Telnet training login
- SMB share listing
- MySQL authentication
- PostgreSQL authentication

PTAS does not execute these commands. It does not store passwords. It does not
provide arbitrary exploit modules, payloads, brute force, DoS, persistence, or
privilege escalation. Any target other than the registered Metasploitable 2
host remains limited to non-destructive assessment recommendations.

Before showing an exercise, PTAS verifies:

1. The manifest profile is exactly `metasploitable2`.
2. The target is one private IP, not loopback, public, or a CIDR.
3. The registered VM UUID still exists.
4. Every enabled VM network adapter is host-only.
5. The registered host-only MAC still matches the VM.
6. The VM is running.
7. At least one clean VM snapshot exists.
8. The target IP resolves to the registered VM MAC.
9. The completed scan target equals the registered IP.
10. The scan contains a sufficiently distinctive Metasploitable 2 service/port fingerprint.
11. The student types `ENABLE ACCESS TESTING` for the current request.

## 2. VMware VMnet1 quick setup for 192.168.178.128

For your classroom lab:

```text
Metasploitable 2 target: 192.168.178.128
Kali source IP:          192.168.178.129
Host-only interface:     vmnet1
```

In VMware settings for the Metasploitable 2 VM, enable only a host-only adapter
on `VMnet1`. Disable NAT, bridged, shared, and any extra adapters. Create a clean
snapshot before class.

From Kali, confirm the route and neighbor identity:

```bash
ip route get 192.168.178.128
ping -c 1 192.168.178.128
ip neigh show 192.168.178.128
vmrun list
vmrun listSnapshots /path/to/Metasploitable2.vmx
```

The route must show `dev vmnet1 src 192.168.178.129`. Register the exact VM:

```bash
./ptas.sh lab-register \
  --name msf2-vmnet1 \
  --provider vmware \
  --target 192.168.178.128 \
  --vm /path/to/Metasploitable2.vmx \
  --interface vmnet1 \
  --kali-source 192.168.178.129
```

Verify the gate:

```bash
./ptas.sh lab-check --name msf2-vmnet1
```

After scanning this exact host with the normal workflow, request one confirmed
exercise at a time:

```bash
./ptas.sh access-test --scan-id 42 --lab msf2-vmnet1
```

PTAS stops before showing each access exercise and requires:

```text
ENABLE ACCESS TESTING
```

For live model-backed coaching during the scan and student terminal work, run:

```bash
ollama serve
./ptas.sh start --provider ollama --model YOUR_INSTALLED_MODEL
```

The model can recommend next validation steps from the current evidence, but
PTAS filters its output and still routes any access-oriented teaching step
through the `access-test` confirmation gate.

### Kali and Metasploitable are both VMware guests

First make the target visible in Kali's neighbor table:

```bash
ping -c 1 192.168.121.130
```

Register it by IP without a `.vmx` path:

```bash
./ptas.sh lab-register \
  --name msf2-local \
  --provider vmware-network \
  --target 192.168.121.130
```

PTAS automatically reads `ip route get` and `ip neigh`. Registration is
refused if the target uses Kali's default/internet interface or if its MAC does
not have a recognized VMware prefix. Because a Kali guest cannot inspect the
physical host's snapshot inventory, keep a clean snapshot on the VMware host;
the exact-IP/MAC/route checks, scan fingerprint, and confirmation gate are
repeated before access exercises are shown.

Then verify and use the completed scan:

```bash
./ptas.sh lab-check --name msf2-local
./ptas.sh access-test --scan-id 33 --lab msf2-local
```

## 3. Install VirtualBox on Kali

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

## 4. Download and import Metasploitable 2

Download Metasploitable 2 only from the location linked by Rapid7's official
documentation. Extract it into a directory that is not shared publicly.

The simplest import process uses the VirtualBox interface:

1. Open VirtualBox.
2. Create a new Linux/Ubuntu 32-bit VM named `Metasploitable2`.
3. Allocate approximately 1 GB RAM and one CPU.
4. Choose **Use an existing virtual hard disk**.
5. Select the extracted Metasploitable `.vmdk` disk.
6. Do not start it until networking is isolated.

## 5. Configure host-only networking

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

## 6. Start the VM and find its private IP

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

## 7. Create a clean snapshot

After confirming the VM starts correctly, create the required baseline:

```bash
VBoxManage snapshot Metasploitable2 take clean-baseline \
  --description "Clean PTAS training baseline"
```

Verify it:

```bash
VBoxManage snapshot Metasploitable2 list --details
```

## 8. Register the VM with PTAS

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

## 9. Verify the registered lab

Make sure the VM is running and its neighbor entry exists, then run:

```bash
ping -c 1 192.168.56.101
./ptas.sh lab-check --name msf2-local
```

Do not continue until PTAS reports that UUID, network, snapshot, and MAC checks
all pass.

## 10. Scan the registered target

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

## 11. Request the first access exercise

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

## 12. Generate JSON and HTML reports

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

## 13. Restore the clean snapshot

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
