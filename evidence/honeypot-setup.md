# Honeypot setup (2026-11-07)

Exposed at about **11:40 UTC**. Built from Azure Cloud Shell.

| Item | Value |
|---|---|
| Resource group | `rg-soc-honeypot` (Japan East), separate from `rg-soc-lab`, own VNet and NSG |
| VM | `vm-honeypot`, Windows Server 2022 Datacenter smalldisk Gen2, Standard_B2als_v2, Trusted Launch |
| Public IP | 52.253.112.30 (Standard SKU; released when the VM is deleted) |
| Exposure | NSG `vm-honeypotNSG` rule `rdp`: TCP 3389 from `*`, Allow |
| Admin account | Non-default username. The strong password was set by the owner and is not stored anywhere in this repo. |
| Logging | Azure Monitor Agent + existing DCR `dcr-soc-signins` (association `dcra-honeypot`), sending 4624/4625 to `SecurityEvent` in `law-soc-lab` |
| Audit policy | Logon: Success and Failure (verified with `auditpol` through Run Command) |

## Commands used

```bash
az group create -n rg-soc-honeypot -l japaneast
az vm create -g rg-soc-honeypot -n vm-honeypot \
  --image MicrosoftWindowsServer:WindowsServer:2022-datacenter-smalldisk-g2:latest \
  --size Standard_B2als_v2 --admin-username <non-default> --public-ip-sku Standard \
  --nsg-rule RDP --assign-identity --security-type TrustedLaunch \
  --enable-secure-boot true --enable-vtpm true          # password typed at the prompt
az vm extension set -g rg-soc-honeypot --vm-name vm-honeypot \
  -n AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --enable-auto-upgrade true
az monitor data-collection rule association create --name dcra-honeypot \
  --rule-id <dcr-soc-signins id> --resource <vm-honeypot id>
```

## Teardown (after evidence is saved)

```bash
az group delete -n rg-soc-honeypot --yes
az monitor data-collection rule association delete --name dcra-honeypot --resource <vm-honeypot id>   # if it lingers
```
