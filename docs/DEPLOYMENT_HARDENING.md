# DORAOps v0.7 Deployment Hardening

DORAOps v0.7 adds a machine-verifiable reference boundary for deployment configuration and imported operational-control evidence. It deliberately separates **reference configuration** from **production effectiveness**.

## Deployment control profile

`DeploymentControlProfile` requires all of the following:

- immutable container image reference using `@sha256:<digest>`;
- non-root execution;
- read-only root filesystem;
- privilege escalation disabled;
- all Linux capabilities dropped;
- `RuntimeDefault` seccomp;
- service-account token automount disabled;
- default-deny egress posture;
- TLS requirement;
- no runtime dependency installation;
- external secret injection;
- explicit resource limits;
- readiness and liveness probes;
- backup/restore testing requirement;
- raw evidence logging disabled;
- `production_effectiveness_determined=false`.

`deployment/kubernetes-reference.yaml` is intentionally non-production and uses an `.invalid` registry. It is a hardening template, not a deployable production manifest.

## Operational-control evidence

`OperationalControlEvidence` imports evidence digests rather than claiming to execute infrastructure controls. Exactly one item is required for each control:

1. immutable deployment;
2. workload runtime security;
3. network egress default deny;
4. external secret injection;
5. external key management;
6. backup/restore evidence;
7. secret-free observability.

Each item requires:

- a distinct SHA-256 artifact digest;
- a non-empty validator identity;
- `negative_path_verified=true`.

The envelope additionally rejects raw endpoints and secrets and structurally fixes:

- `production_effectiveness_determined=false`;
- `dora_compliance_determined=false`;
- `supervisory_acceptance_determined=false`;
- `requires_human_review=true`.

A document may state whether evidence was collected in a production environment, but that flag is contextual metadata and does not convert the evidence into a production-effectiveness determination.

## What this milestone does not prove

Passing v0.7 checks does not prove that a real Kubernetes cluster, container runtime, network policy implementation, secret manager, KMS/HSM, backup platform, monitoring platform, retention system or disaster-recovery process is effective in production. Those require environment-specific validation and accountable human review.
