# Garm External Provider For Azure

The Azure external provider allows [garm](https://github.com/cloudbase/garm) to create Linux and Windows runners on top of Azure virtual machines.

## Build

Clone the repo:

```bash
git clone https://github.com/cloudbase/garm-provider-azure
```

Build the binary:

```bash
cd garm-provider-azure
go build .
```

Copy the binary on the same system where garm is running, and [point to it in the config](https://github.com/cloudbase/garm/blob/main/doc/providers.md#the-external-provider).

## Configure

The config file for this external provider is a simple toml used to configure the azure credentials it needs to spin up virtual machines.

For now, only service principles credentials and azure managed identity are supported. An example can be found [in the testdata folder](./testdata/config.toml).

```toml
location = "westeurope"

[credentials]
subscription_id = "sample_sub_id"

    # The service principle service credentials can be used when azure managed identity
    # is not available.
    [credentials.service_principal]
    # you can create a SP using:
    # az ad sp create-for-rbac --scopes /subscriptions/<subscription ID> --role Contributor
    tenant_id = "sample_tenant_id"
    client_id = "sample_client_id"
    client_secret = "super secret client secret"

    # The managed identity token source is always added to the chain of possible authentication
    # sources. The client ID can be overwritten if needed. 
    [credentials.managed_identity]
    # The client ID to use. This config value is optional.
    client_id = "sample_client_id"
```

## Creating a pool

After you [add it to garm as an external provider](https://github.com/cloudbase/garm/blob/main/doc/providers.md#the-external-provider), you need to create a pool that uses it. Assuming you named your external provider as ```azure``` in the garm config, the following command should create a new pool:

```bash
garm-cli pool create \
    --os-type windows \
    --enabled=true \
    --flavor Standard_F2s \
    --image MicrosoftWindowsServer:WindowsServer:2022-Datacenter:latest \
    --min-idle-runners 1 \
    --repo f0b1c1c8-b605-4560-adb7-79b95e2e470c \
    --tags azure,golang,win2 \
    --provider-name azure
```

This will create a new Windows runner pool for the repo with ID ```f0b1c1c8-b605-4560-adb7-79b95e2e470c``` on azure, using the image ```MicrosoftWindowsServer:WindowsServer:2022-Datacenter:latest``` and VM size ```Standard_F2s```. You can, of course, tweak the values in the above command to suit your needs.

Here an example for a Linux pool:

```bash
garm-cli pool create \
   --enabled=true \
   --flavor Standard_F8s \
   --min-idle-runners 1 --max-runners 8 \
   --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:22.04.202206040 \
   --org=a2f1c7c8-b605-4560-adb7-79b95e2e462d \
   --tags=azure,ubuntu \
   --provider-name azure
```

Always find a recent image to use. For example to see available Debian images, run something like `az vm image list --all --publisher Debian --offer debian-11 --all | less`.

Each VM is created in it's own resource group with it's own virtual network, separate from all other runners.

## Tweaking the provider

Garm supports sending opaque json encoded configs to the IaaS providers it hooks into. This allows the providers to implement some very provider specific functionality that doesn't necessarily translate well to other providers. Features that may exists on Azure, may not exist on AWS or OpenStack and vice versa.

To this end, this provider supports the following extra specs schema:

```json
{
    "$schema": "http://cloudbase.it/garm-provider-azure/schemas/extra_specs#",
    "type": "object",
    "description": "Schema defining supported extra specs for the Garm Azure Provider",
    "properties": {
        "allocate_public_ip": {
            "type": "boolean",
            "description": "Allocate a public IP to the VM."
        },
        "confidential": {
            "type": "boolean",
            "description": "The selected virtual machine size is confidential."
        },
        "use_ephemeral_storage": {
            "type": "boolean",
            "description": "Use ephemeral storage for the VM."
        },
        "use_accelerated_networking": {
            "type": "boolean",
            "description": "Use accelerated networking for the VM."
        },
        "open_inbound_ports": {
            "type": "object",
            "description": "A map of protocol to list of inbound ports to open.",
            "properties": {
                "Tcp": {
                    "type": "array",
                    "description": "List of ports to open.",
                    "items": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    }
                },
                "Udp": {
                    "type": "array",
                    "description": "List of ports to open.",
                    "items": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    }
                }
            }
        },
        "storage_account_type": {
            "type": "string",
            "description": "Azure storage account type. Default is Standard_LRS."
        },
        "virtual_network_cidr": {
            "type": "string",
            "description": "The CIDR for the virtual network."
        },
        "disk_size_gb": {
            "type": "integer",
            "description": "The size of the root disk in GB. Default is 127 GB."
        },
        "extra_tags": {
            "type": "object",
            "description": "Extra tags that will get added to all VMs spawned in a pool."
        },
        "ssh_public_keys": {
            "type": "array",
            "description": "SSH public keys to add to the admin user on Linux runners.",
            "items": {
                "type": "string"
            }
        }
    }
}
```

An example extra specs json would look like this:

```json
{
    "allocate_public_ip": true,
    "open_inbound_ports": {
        "Tcp": [22, 80]
    },
    "storage_account_type": "Standard_LRS",
    "disk_size_gb": 200,
    "extra_tags": {
        "my_custom_tag": "some value"
    },
    "ssh_public_keys": [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC2oT7j/+elHY9U2ibgk2R...."
    ]
}
```

To set it on an existing pool, simply run:

```bash
garm-cli pool update --extra-specs='{"allocate_public_ip": true}' <POOL_ID>
```

You can also set a spec when creating a new pool, using the same flag.

Workers in that pool will be created taking into account the specs you set on the pool.
