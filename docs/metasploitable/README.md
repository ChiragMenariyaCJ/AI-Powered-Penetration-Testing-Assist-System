# Metasploitable 2 setup from a Kali VMware guest

This guide is for the classroom arrangement where Kali Linux and
Metasploitable 2 are separate VMware guests. PTAS runs inside Kali, so it cannot
normally read the `.vmx` file stored on the physical host.

PTAS provides `vmware-network` registration for this topology. It uses the
current Metasploitable IP and automatically records Kali's route, isolated
interface, source IP, and the target's VMware MAC address. If VMware changes the
target IP, rerun the same script with the new address.

## VMware configuration

On the physical host, configure both guests with a shared host-only VMware
network. Metasploitable must not have bridged or public exposure. Keep a clean
Metasploitable snapshot on the physical host before access testing.

Inside Kali, find the target IP from the Metasploitable console using:

```bash
ifconfig
```

Confirm that Kali can reach it:

```bash
ping -c 1 192.168.121.130
```

## Standalone setup command

After running the normal Kali setup, register the current IP:

```bash
./metasploitable-setup.sh --target 192.168.121.130
```

The default lab name is `msf2-local`. A classroom can select another name:

```bash
./metasploitable-setup.sh \
  --target 192.168.56.101 \
  --name classroom-msf2
```

The script performs these steps:

1. Confirms that the IP responds and populates Kali's neighbor table.
2. Confirms that the route does not use Kali's default/internet interface.
3. Records the current VMware MAC, Kali interface, and Kali source IP.
4. Creates or replaces `.ptas/labs/LAB_NAME.json`.
5. Runs `lab-check` immediately.
6. Saves the selected IP and lab name in `.env`.

## Configure it during the main Kali setup

Supply the IP when running the main installer:

```bash
PTAS_METASPLOITABLE_IP=192.168.121.130 ./kali-setup.sh
```

An optional custom lab name can be supplied at the same time:

```bash
PTAS_METASPLOITABLE_IP=192.168.56.101 \
PTAS_METASPLOITABLE_LAB=classroom-msf2 \
./kali-setup.sh
```

If no IP is supplied, the normal PTAS installation completes and prints the
standalone command for configuring Metasploitable later.

## When the Metasploitable IP changes

Use the same lab name and the new IP. The saved network identity is replaced:

```bash
./metasploitable-setup.sh \
  --target 192.168.121.145 \
  --name msf2-local
```

Do not edit the manifest manually. The script rechecks the route and MAC before
writing the new registration.

## Start access exercises after a scan

For an existing final scan such as scan 33:

```bash
./metasploitable-setup.sh \
  --target 192.168.121.130 \
  --scan-id 33
```

Or run the gate separately:

```bash
./ptas.sh lab-check --name msf2-local
./ptas.sh access-test --scan-id 33 --lab msf2-local
```

PTAS verifies that the scan target and service fingerprint match the registered
Metasploitable guest. Type `ENABLE ACCESS TESTING` only after reviewing the
displayed identity and target.

The live dashboard also discovers the matching lab automatically. After a scan
finishes, it displays `METASPLOITABLE 2 LAB MODE ENABLED`. If Ollama determines
that evidence-only validation is complete, the next recommendation becomes the
scan-specific `access-test` gate rather than an empty-model warning.

If the lab was registered after an existing dashboard had already loaded its
scan, restart that dashboard so it performs the new identity check. For example:

```bash
./ptas.sh dashboard \
  --event-log .ptas/student-20260824-173752.jsonl \
  --transcript .ptas/student-20260824-173752.typescript
```

## Common errors

`No neighbor MAC found` means the VM has not recently communicated with Kali.
Run `ping -c 1 TARGET_IP` and retry.

`Target uses Kali's default network interface` means the lab is not on a
separate interface from Kali's default route. Change both VMware guests to the
same host-only network and retry.

`MAC does not use a recognized VMware prefix` means the IP may belong to a
different device. Confirm the address from the Metasploitable console rather
than bypassing the check.
