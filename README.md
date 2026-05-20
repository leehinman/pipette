# pipette

A [swamp](https://github.com/systeminit/swamp) extensions repository for running Elastic Stack benchmarks on local VMs. It provides custom swamp models for managing Multipass VMs, the Elastic Stack, Elastic Agents, and [spigot](https://github.com/elastic/spigot) log generation — wired together in a workflow that measures document ingestion throughput (events/second).

## Prerequisites

- [swamp](https://github.com/systeminit/swamp) installed and initialized
- [Multipass](https://multipass.run/) installed (for VM provisioning on macOS/Linux)
- An SSH key pair accessible to swamp (or the SSH agent via YubiKey)

## Getting Started

### 1. Clone and initialize

```sh
git clone https://github.com/leeehinman/pipette
cd pipette
```

### 2. Load the extensions

The extensions live in `extensions/models/`. Load them into swamp:

```sh
swamp doctor extensions --repair
```

Verify they loaded:

```sh
swamp model type describe @leeehinman/elastic-stack --json | grep version
swamp model type describe @leeehinman/elastic-agent --json | grep version
swamp model type describe @leeehinman/multipass --json | grep version
swamp model type describe @leeehinman/spigot --json | grep version
```

### 3. Create a vault for secrets

```sh
swamp vault create elastic-stack-dev local_encryption --auto-generate
```

*NOTE* swamp will figure this out this is missing and prompt you if you don't do this step.



## Extensions

| Extension | Type | Description |
|---|---|---|
| `@leeehinman/multipass` | model | Create and manage Multipass VMs (launch, delete, start, stop, sync) |
| `@leeehinman/elastic-stack` | model | Install and manage Elastic Stack across 3 SSH-reachable hosts |
| `@leeehinman/elastic-agent` | model | Install and enroll elastic-agent via SSH, connected to Fleet |
| `@leeehinman/spigot` | model | Build and run [spigot](https://github.com/elastic/spigot) to generate synthetic Apache CLF log files |

## Benchmark Workflow

The `spigot-benchmark` workflow (`workflows/workflow-da5791c3-*.yaml`) runs a full end-to-end ingestion benchmark:

1. **install-stack** — start Elastic Stack, clear the benchmark data stream
2. **provision-vms** — launch 3 Multipass agent VMs in parallel
3. **install-agents + install-spigot** — enroll elastic-agent and install spigot on each VM
4. **add-apache-integration** — add the Apache access log integration to the Fleet policy
5. **verify-policy** — confirm all agents have the policy applied
6. **generate-logs** — run spigot on each VM to produce log files
7. **ingest** — record the start timestamp, then start the agents so filebeat begins shipping
8. **measure** — wait for all documents to land in Elasticsearch, then compute EPS

Run it:

```sh
swamp workflow run spigot-benchmark --input countPerAgent=100000
```

The workflow outputs events-per-second measured via `min`/`max` of `event.ingested` in Elasticsearch.

## Structure

```
extensions/models/   # swamp extension source (TypeScript/Deno)
models/              # swamp model instance definitions
vaults/              # encrypted vault configuration
workflows/           # workflow YAML definitions
manifest.yaml        # extension package manifest (@leeehinman/elastic-stack)
cloud-init-elastic-dev.yaml  # cloud-init template for Multipass VMs
```
