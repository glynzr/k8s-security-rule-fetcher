# Kubernetes security rules — cross-scanner catalogue

Generated 2026-09-30 07:11 UTC from 9 scanners, 1076 rules. Rules are grouped by **domain → topic** so equivalent checks from different tools sit together.

| Tool | Rules | Upstream commit |
|---|---:|---|
| kube-bench | 133 | [`e0ffe5da8f`](https://github.com/aquasecurity/kube-bench/tree/e0ffe5da8fe16192074773b7a7b20da825f15827) |
| kubescape | 290 | [`e67b7d42a0`](https://github.com/kubescape/regolibrary/tree/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e) |
| trivy | 165 | [`3ae9f4cc19`](https://github.com/aquasecurity/trivy-checks/tree/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b) |
| checkov | 119 | [`29ba1746d0`](https://github.com/bridgecrewio/checkov/tree/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d) |
| kube-linter | 63 | [`a4ca2547fc`](https://github.com/stackrox/kube-linter/tree/a4ca2547fc42016044175588e3a266c2639125fb) |
| polaris | 44 | [`4ced8e86db`](https://github.com/FairwindsOps/polaris/tree/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a) |
| kyverno | 121 | [`3634004722`](https://github.com/kyverno/policies/tree/36340047222cf73e8ef2766adeaff46f2aad2362) |
| prowler | 92 | [`04511f339e`](https://github.com/prowler-cloud/prowler/tree/04511f339e2cc13857f8d876d689857429f65edf) |
| gatekeeper | 49 | [`d2b86f87b0`](https://github.com/open-policy-agent/gatekeeper-library/tree/d2b86f87b0c98922d0765f6829bdabd75b3348e5) |

kube-bench benchmarks included: cis-1.11

## Contents

- [Audit logging & monitoring](#audit-logging--monitoring) — 34 rules
- [Cluster policies & governance](#cluster-policies--governance) — 9 rules
- [Control plane: API server](#control-plane-api-server) — 117 rules
- [Control plane: controller manager & scheduler](#control-plane-controller-manager--scheduler) — 36 rules
- [General / other](#general--other) — 5 rules
- [Host files: permissions & ownership](#host-files-permissions--ownership) — 99 rules
- [Known vulnerabilities & legacy components](#known-vulnerabilities--legacy-components) — 26 rules
- [Managed Kubernetes (EKS/AKS/GKE) & cloud](#managed-kubernetes-eksaksgke--cloud) — 36 rules
- [Namespaces & multi-tenancy](#namespaces--multi-tenancy) — 24 rules
- [Network security](#network-security) — 72 rules
- [RBAC & identity](#rbac--identity) — 109 rules
- [Resources, availability & reliability](#resources-availability--reliability) — 88 rules
- [Secrets & encryption](#secrets--encryption) — 51 rules
- [Supply chain & images](#supply-chain--images) — 33 rules
- [Worker nodes: kubelet & kube-proxy](#worker-nodes-kubelet--kube-proxy) — 98 rules
- [Workload security (Pod Security)](#workload-security-pod-security) — 194 rules
- [etcd](#etcd) — 45 rules

## Audit logging & monitoring

### Audit logging  
_26 rules · tools: checkov, gatekeeper, kube-bench, kubescape, prowler, trivy_

- `kubescape` **C-0130** · HIGH · CIS cis-v1.10.0:1.2.16; cis-v1.12.0:1.2.16 — Ensure that the API Server --audit-log-path argument is set
  - _What:_ Enable auditing on the Kubernetes API Server and set the desired audit log path.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--audit-log-path` parameter to a suitable path and file where you would like audit logs to be written, for example: ``` --audit-log-path=/var/log/apiserver/audit.log ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0130-ensurethattheapiserverauditlogpathargumentisset.json)
- `prowler` **apiserver_audit_log_path_set** · HIGH — API server pod has --audit-log-path set
  - _What:_ **Kubernetes API server** uses an **audit log path** configured via `--audit-log-path` on its containers to persist API request events
  - _Fix:_ Enable and harden **audit logging** by setting `--audit-log-path`. *If centralizing*, use a webhook backend. Define a focused audit policy, enforce **least privilege** to logs, rotate/retain them, forward to centralized monitoring, and regularly review events for **defense in depth**. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_audit_log_path_set/apiserver_audit_log_path_set.metadata.json)
- `kubescape` **C-0067** · MEDIUM · CIS cis-eks-t1.7.0:2.1.1; cis-eks-t1.8.0:2.1.1; cis-gke-v1.9.0:5.7.1 — Audit logs enabled
  - _What:_ Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes
  - _Fix:_ Turn on audit logging for your cluster. Look at the vendor guidelines for more details
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0067-auditlogsenabled.json)
- `kubescape` **C-0131** · MEDIUM · CIS cis-v1.10.0:1.2.17; cis-v1.12.0:1.2.17 — Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate
  - _What:_ Retain the logs for at least 30 days or as appropriate.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--audit-log-maxage` parameter to 30 or as an appropriate number of days: ``` --audit-log-maxage=30 ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0131-ensurethattheapiserverauditlogmaxageargumentissetto30orasappropriate.json)
- `kubescape` **C-0132** · MEDIUM · CIS cis-v1.10.0:1.2.18; cis-v1.12.0:1.2.18 — Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate
  - _What:_ Retain 10 or an appropriate number of old log files.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--audit-log-maxbackup` parameter to 10 or to an appropriate value. ``` --audit-log-maxbackup=10 ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0132-ensurethattheapiserverauditlogmaxbackupargumentissetto10orasappropriate.json)
- `kubescape` **C-0133** · MEDIUM · CIS cis-v1.10.0:1.2.19; cis-v1.12.0:1.2.19 — Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate
  - _What:_ Rotate log files on reaching 100 MB or as appropriate.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--audit-log-maxsize` parameter to an appropriate size in MB. For example, to set it as 100 MB: ``` --audit-log-maxsize=100 ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0133-ensurethattheapiserverauditlogmaxsizeargumentissetto100orasappropriate.json)
- `kubescape` **C-0160** · MEDIUM · CIS cis-v1.10.0:3.2.1; cis-v1.12.0:3.2.1 — Ensure that a minimal audit policy is created
  - _What:_ Kubernetes can audit the details of requests made to the API server. The `--audit-policy-file` flag must be set for this logging to be enabled.
  - _Fix:_ Create an audit policy file for your cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0160-ensurethataminimalauditpolicyiscreated.json)
- `kubescape` **C-0161** · MEDIUM · CIS cis-v1.10.0:3.2.2; cis-v1.12.0:3.2.2 — Ensure that the audit policy covers key security concerns
  - _What:_ Ensure that the audit policy created for the cluster covers key security concerns.
  - _Fix:_ Consider modification of the audit policy in use on the cluster to include these items, at a minimum.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0161-ensurethattheauditpolicycoverskeysecurityconcerns.json)
- `prowler` **apiserver_audit_log_maxage_set** · MEDIUM — API server pod has --audit-log-maxage set to 30 (or the cluster-configured value)
  - _What:_ **Kubernetes API server** audit logging retention is governed by `--audit-log-maxage`. This evaluates whether the configured value (e.g., `30` days) is set consistently across API server containers to retain audit events for a sufficient period.
  - _Fix:_ Set `--audit-log-maxage` to at least `30` days (or your policy) to support **forensics**. Align rotation with `--audit-log-maxbackup` and `--audit-log-maxsize`. Forward logs to a tamper-resistant central store, enforce **least privilege** on access, and periodically validate retention coverage. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_audit_log_maxage_set/apiserver_audit_log_maxage_set.metadata.json)
- `prowler` **apiserver_audit_log_maxbackup_set** · MEDIUM — API server pod has --audit-log-maxbackup set to 10 or the configured value
  - _What:_ **Kubernetes API server audit logging** uses `--audit-log-maxbackup` to set how many rotated audit log files are kept. This evaluates whether that value is explicitly configured as `10` or an approved organizational setting across API server containers.
  - _Fix:_ Establish explicit **audit log retention**. Set `--audit-log-maxbackup` to `10` or higher based on data sensitivity, and align with `--audit-log-maxsize` and `--audit-log-maxage`. Forward logs to centralized, immutable storage, restrict access, and monitor rotation. Apply **defense in depth** and …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_audit_log_maxbackup_set/apiserver_audit_log_maxbackup_set.metadata.json)
- `prowler` **apiserver_audit_log_maxsize_set** · MEDIUM — API server pod has --audit-log-maxsize set to 100 MB or the configured value
  - _What:_ **Kubernetes API server** uses `--audit-log-maxsize` to cap audit log files. The check expects `100 MB` or a policy-approved value, indicating rotation occurs when a log reaches that size.
  - _Fix:_ Set `--audit-log-maxsize` to `100 MB` or your approved baseline to ensure predictable rotation. Pair with sensible retention (`--audit-log-maxage`, `--audit-log-maxbackup`), forward to a central store, and monitor capacity. This enforces **defense in depth** and preserves reliable auditability. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_audit_log_maxsize_set/apiserver_audit_log_maxsize_set.metadata.json)
- `trivy` **KCV-0019** · LOW — Ensure that the --audit-log-path argument is set
  - _What:_ [API server] Enable auditing on the Kubernetes API Server and set the desired audit log path.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-path parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_audit_log_path.rego)
- `trivy` **KCV-0020** · LOW — Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - _What:_ [API server] Retain the logs for at least 30 days or as appropriate.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_audit_log_maxage.rego)
- `trivy` **KCV-0021** · LOW — Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - _What:_ [API server] Retain 10 or an appropriate number of old log files.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_audit_log_maxbackup.rego)
- `trivy` **KCV-0022** · LOW — Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - _What:_ [API server] Rotate log files on reaching 100 MB or as appropriate.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxsize parameter to an appropriate size in MB
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_audit_log_maxsize.rego)
- `checkov` **CKV_K8S_91** — Ensure that the --audit-log-path argument is set
  - _What:_ [API server] Ensure that the --audit-log-path argument is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLog.py)
- `checkov` **CKV_K8S_92** — Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - _What:_ [API server] Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxAge.py)
- `checkov` **CKV_K8S_93** — Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - _What:_ [API server] Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxBackup.py)
- `checkov` **CKV_K8S_94** — Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - _What:_ [API server] Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuditLogMaxSize.py)
- `gatekeeper` **noupdateserviceaccount** — Block updating Service Account
  - _What:_ Blocks updating the service account on resources that abstract over Pods. This policy is ignored in audit mode.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/noupdateserviceaccount/template.yaml)
- `kube-bench` **1.2.16** · CIS cis-1.11:1.2.16 — Ensure that the --audit-log-path argument is set
  - _What:_ [API Server] Ensure that the --audit-log-path argument is set
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --audit-log-path parameter to a suitable path and file where you would like audit logs to be written, for example, --audit-log-path=/var/log/apiserver/audit.log
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.17** · CIS cis-1.11:1.2.17 — Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - _What:_ [API Server] Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days, for example, --audit-log-maxage=30
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.18** · CIS cis-1.11:1.2.18 — Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - _What:_ [API Server] Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value. For example, --audit-log-maxbackup=10
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.19** · CIS cis-1.11:1.2.19 — Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - _What:_ [API Server] Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --audit-log-maxsize parameter to an appropriate size in MB. For example, to set it as 100 MB, --audit-log-maxsize=100
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **3.2.1** · manual · CIS cis-1.11:3.2.1 — Ensure that a minimal audit policy is created
  - _What:_ [Logging] Ensure that a minimal audit policy is created
  - _Fix:_ Create an audit policy file for your cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/controlplane.yaml)
- `kube-bench` **3.2.2** · manual · CIS cis-1.11:3.2.2 — Ensure that the audit policy covers key security concerns
  - _What:_ [Logging] Ensure that the audit policy covers key security concerns
  - _Fix:_ Review the audit policy provided for the cluster and ensure that it covers at least the following areas, - Access to Secrets managed by the cluster. Care should be taken to only log Metadata for requests to Secrets, ConfigMaps, and TokenReviews, in order to avoid risk of logging sensitive data. - …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/controlplane.yaml)

### Deprecated APIs / versions  
_1 rules · tools: gatekeeper_

- `gatekeeper` **verifydeprecatedapi** — Verify deprecated APIs
  - _What:_ Verifies deprecated Kubernetes APIs to ensure all the API versions are up to date. This template does not apply to audit as audit looks at the resources which are already present in the cluster with non-deprecated API versions.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/verifydeprecatedapi/template.yaml)

### Secrets in env vars / config  
_1 rules · tools: kyverno_

- `kyverno` **secrets-not-from-env-vars** · MEDIUM — Disallow Secrets from Env Vars
  - _What:_ Secrets used as environment variables containing sensitive information may, if not carefully controlled, be printed in log output which could be visible to unauthorized people and captured in forwarding applications. This policy disallows using Secrets as environment variables.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/disallow-secrets-from-env-vars/disallow-secrets-from-env-vars.yaml)

### ServiceAccount token automount  
_1 rules · tools: kube-bench_

- `kube-bench` **3.1.2** · manual · CIS cis-1.11:3.1.2 — Service account token authentication should not be used for users
  - _What:_ [Authentication and Authorization] Service account token authentication should not be used for users
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of service account tokens.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/controlplane.yaml)

### TLS / certificates / ciphers  
_1 rules · tools: kube-bench_

- `kube-bench` **3.1.1** · manual · CIS cis-1.11:3.1.1 — Client certificate authentication should not be used for users
  - _What:_ [Authentication and Authorization] Client certificate authentication should not be used for users
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of client certificates.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/controlplane.yaml)

### hostPath volumes  
_1 rules · tools: kyverno_

- `kyverno` **ensure-readonly-hostpath** · MEDIUM — Ensure Read Only hostPath
  - _What:_ Pods which are allowed to mount hostPath volumes in read/write mode pose a security risk even if confined to a "safe" file system on the host and may escape those confines (see https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts). The only true way to ensure safety is to enforce that all Pods mounting hostPath volumes do so in read only mode. This policy checks all containers for …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/ensure-readonly-hostpath/ensure-readonly-hostpath.yaml)

### Other  
_3 rules · tools: kube-bench, kubescape, trivy_

- `kubescape` **C-0031** · MEDIUM — Delete Kubernetes events
  - _What:_ Attackers may delete Kubernetes events to avoid detection of their activity in the cluster. This control identifies all the subjects that can delete Kubernetes events.
  - _Fix:_ You should follow the least privilege principle. Minimize the number of subjects who can delete Kubernetes events. Avoid using these subjects in the daily operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0031-deletekubernetesevents.json)
- `trivy` **KSV-0042** · MEDIUM — Delete pod logs
  - _What:_ Used to cover attacker’s tracks, but most clusters ship logs quickly off-cluster.
  - _Fix:_ Remove verbs 'delete' and 'deletecollection' for resource 'pods/log' for Role and ClusterRole
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/delete_pod_logs.rego)
- `kube-bench` **3.1.3** · manual · CIS cis-1.11:3.1.3 — Bootstrap token authentication should not be used for users
  - _What:_ [Authentication and Authorization] Bootstrap token authentication should not be used for users
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of bootstrap tokens.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/controlplane.yaml)


## Cluster policies & governance

### Deprecated APIs / versions  
_3 rules · tools: kube-linter, kyverno, trivy_

- `trivy` **KSV-0107** · LOW — The deprecated 'apiVersion' and 'kind' should not be used
  - _What:_ The specified 'apiVersion' and 'kind' are deprecated and are planned to be removed
  - _Fix:_ Migrate resource to new API
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/outdated_api.rego)
- `kube-linter` **no-extensions-v1beta** — No extensions v1beta
  - _What:_ Indicates when objects use deprecated API versions under extensions/v1beta.
  - _Fix:_ Migrate using the apps/v1 API versions for the objects. Refer to https://kubernetes.io/blog/2019/07/18/api-deprecations-in-1-16/ for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-extensions-v1beta.yaml)
- `kyverno` **check-deprecated-apis** — Check deprecated APIs in VPOL
  - _What:_ Kubernetes APIs are sometimes deprecated and removed after a few releases. As a best practice, older API versions should be replaced with newer versions. This policy validates for APIs that are deprecated or scheduled for removal.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/check-deprecated-apis/check-deprecated-apis.yaml)

### TLS / certificates / ciphers  
_1 rules · tools: gatekeeper_

- `gatekeeper` **k8srequiredresources** — Required Resources
  - _What:_ Requires containers to have defined resources set. https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/containerresources/template.yaml)

### Other  
_5 rules · tools: kube-linter, kyverno_

- `kyverno` **application-prevent-default-project** · MEDIUM — Prevent Use of Default Project in CEL expressions
  - _What:_ This policy prevents the use of the default project in an Application.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/argo-vpol/application-prevent-default-project/application-prevent-default-project.yaml)
- `kyverno` **check-env-vars** · MEDIUM — Check Environment Variables
  - _What:_ Environment variables control many aspects of a container's execution and are often the source of many different configuration settings. Being able to ensure that the value of a specific environment variable either is or is not set to a specific string is useful to maintain such controls. This policy checks every container to ensure that if the `DISABLE_OPA` environment variable is defined, it …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-env-vars/check-env-vars.yaml)
- `kyverno` **restrict-jobs** · MEDIUM — Restrict Jobs
  - _What:_ Jobs can be created directly and indirectly via a CronJob controller. In some cases, users may want to only allow Jobs if they are created via a CronJob. This policy restricts Jobs so they may only be created by a CronJob.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-jobs/restrict-jobs.yaml)
- `kube-linter` **restart-policy** — Restart policy
  - _What:_ Indicates when a deployment-like object does not use a restart policy
  - _Fix:_ Set up the restart policy for your object to 'Always' or 'OnFailure' to increase the fault tolerance.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/restart-policy.yaml)
- `kube-linter` **sorted-keys** — Sorted keys
  - _What:_ Check that YAML keys are sorted in alphabetical order wherever possible.
  - _Fix:_ Ensure that keys in your YAML manifest are sorted in alphabetical order to improve consistency and readability.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/sorted-keys.yaml)


## Control plane: API server

### API / kubelet authn & authz flags  
_21 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_auth_mode_not_always_allow** · CRITICAL — API server pod does not use the AlwaysAllow authorization mode
  - _What:_ **Kubernetes API server** authorization is evaluated via the `--authorization-mode` setting to detect any use of `AlwaysAllow`. The focus is whether policy-driven authorizers are configured instead of an allow-all mode.
  - _Fix:_ Use policy-based authorization and avoid `AlwaysAllow`. Prefer `RBAC` with `Node` (and Webhook if needed) to enforce **least privilege** and **separation of duties**. Define granular roles, avoid broad bindings like `cluster-admin`, and audit access for **defense in depth**. Steps: 1. SSH to the …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_auth_mode_not_always_allow/apiserver_auth_mode_not_always_allow.metadata.json)
- `kubescape` **C-0113** · HIGH · CIS cis-v1.10.0:1.2.1; cis-v1.12.0:1.2.1 — Ensure that the API Server --anonymous-auth argument is set to false
  - _What:_ Disable anonymous requests to the API server.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the below parameter. ``` --anonymous-auth=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0113-ensurethattheapiserveranonymousauthargumentissettofalse.json)
- `kubescape` **C-0118** · HIGH · CIS cis-v1.10.0:1.2.6; cis-v1.12.0:1.2.6 — Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow
  - _What:_ Do not always authorize all requests.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--authorization-mode` parameter to values other than `AlwaysAllow`. One such example could be as below. ``` --authorization-mode=RBAC ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0118-ensurethattheapiserverauthorizationmodeargumentisnotsettoalwaysallow.json)
- `kubescape` **C-0120** · HIGH · CIS cis-v1.10.0:1.2.8; cis-v1.12.0:1.2.8 — Ensure that the API Server --authorization-mode argument includes RBAC
  - _What:_ Turn on Role Based Access Control.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--authorization-mode` parameter to a value that includes `RBAC`, for example: ``` --authorization-mode=Node,RBAC ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0120-ensurethattheapiserverauthorizationmodeargumentincludesrbac.json)
- `kubescape` **C-0128** · HIGH — Ensure that the API Server --secure-port argument is not set to 0
  - _What:_ Do not disable the secure port.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and either remove the `--secure-port` parameter or set it to a different (non-zero) desired port.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0128-ensurethattheapiserversecureportargumentisnotsetto0.json)
- `prowler` **apiserver_anonymous_requests** · HIGH — API server pod has anonymous-auth disabled
  - _What:_ **Kubernetes API server** anonymous authentication configuration, identified by `--anonymous-auth=true`. With this setting, unauthenticated requests are mapped to `system:anonymous` and processed by the server.
  - _Fix:_ Require **authenticated access** for all API requests and avoid reliance on anonymous users. Enforce **least privilege RBAC** for explicit principals only. *If health checks must be public*, restrict to minimal paths and methods. Add **network segmentation**, mutual TLS, and **audit logging** for …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_anonymous_requests/apiserver_anonymous_requests.metadata.json)
- `prowler` **apiserver_auth_mode_include_node** · HIGH — API server pod has Node in --authorization-mode
  - _What:_ **Kubernetes API server** authorization settings include the **Node authorizer** in `--authorization-mode`. The evaluation looks for `Node` among the configured modes.
  - _Fix:_ Include **Node** alongside **RBAC** by adding `Node` to `--authorization-mode`. Apply **least privilege** so kubelets are limited to their node and bound pods, and use `NodeRestriction` for **defense in depth**. Periodically review kubelet permissions and audit access. Steps: 1. SSH to the control …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_auth_mode_include_node/apiserver_auth_mode_include_node.metadata.json)
- `trivy` **KCV-0001** · MEDIUM — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [API server] Disable anonymous requests to the API server.
  - _Fix:_ Set '--anonymous-auth' to 'false'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_anonymous_auth.rego)
- `trivy` **KCV-0007** · LOW — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [API server] Do not always authorize all requests.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to values other than AlwaysAllow.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_authorization_mode.rego)
- `trivy` **KCV-0009** · LOW — Ensure that the --authorization-mode argument includes RBAC
  - _What:_ [API server] Turn on Role Based Access Control.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes RBAC.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_authorization_mode_includes_rbac.rego)
- `trivy` **KCV-0017** · LOW — Ensure that the --secure-port argument is not set to 0
  - _What:_ [API server] Do not disable the secure port.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --secure-port parameter or set it to a different (non-zero) desired port.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_secure_port.rego)
- `checkov` **CKV_K8S_68** — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [API server] Ensure that the --anonymous-auth argument is set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAnonymousAuth.py)
- `checkov` **CKV_K8S_74** — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [API server] Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeNotAlwaysAllow.py)
- `checkov` **CKV_K8S_75** — Ensure that the --authorization-mode argument includes Node
  - _What:_ [API server] Ensure that the --authorization-mode argument includes Node
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeNode.py)
- `checkov` **CKV_K8S_77** — Ensure that the --authorization-mode argument includes RBAC
  - _What:_ [API server] Ensure that the --authorization-mode argument includes RBAC
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeRBAC.py)
- `checkov` **CKV_K8S_88** — Ensure that the --insecure-port argument is set to 0
  - _What:_ [API server] Ensure that the --insecure-port argument is set to 0
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerInsecurePort.py)
- `checkov` **CKV_K8S_89** — Ensure that the --secure-port argument is not set to 0
  - _What:_ [API server] Ensure that the --secure-port argument is not set to 0
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerSecurePort.py)
- `kube-bench` **1.2.1** · manual · CIS cis-1.11:1.2.1 — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [API Server] Ensure that the --anonymous-auth argument is set to false
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the below parameter. --anonymous-auth=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.6** · CIS cis-1.11:1.2.6 — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [API Server] Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --authorization-mode parameter to values other than AlwaysAllow. One such example could be as below. --authorization-mode=RBAC
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.7** · CIS cis-1.11:1.2.7 — Ensure that the --authorization-mode argument includes Node
  - _What:_ [API Server] Ensure that the --authorization-mode argument includes Node
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --authorization-mode parameter to a value that includes Node. --authorization-mode=Node,RBAC
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.8** · CIS cis-1.11:1.2.8 — Ensure that the --authorization-mode argument includes RBAC
  - _What:_ [API Server] Ensure that the --authorization-mode argument includes RBAC
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --authorization-mode parameter to a value that includes RBAC, for example `--authorization-mode=Node,RBAC`.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Admission plugins  
_26 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_no_always_admit_plugin** · CRITICAL — API server pod does not have the AlwaysAdmit admission control plugin enabled
  - _What:_ **Kubernetes API server** configuration is inspected for the `AlwaysAdmit` admission plugin in `--enable-admission-plugins`. If `AlwaysAdmit` is configured, the server accepts all admission requests without running other admission controllers.
  - _Fix:_ Exclude `AlwaysAdmit` from API server settings. Use a **deny-by-default** admission posture and enable only necessary controllers to enforce policy and limits (e.g., PodSecurity, ResourceQuota, LimitRanger). Apply **least privilege**, regularly review admission configuration, and audit API …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_no_always_admit_plugin/apiserver_no_always_admit_plugin.metadata.json)
- `kubescape` **C-0122** · HIGH · CIS cis-v1.10.0:1.2.10; cis-v1.12.0:1.2.10 — Ensure that the admission control plugin AlwaysAdmit is not set
  - _What:_ Do not allow all requests.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and either remove the `--enable-admission-plugins` parameter, or set it to a value that does not include `AlwaysAdmit`.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0122-ensurethattheadmissioncontrolpluginalwaysadmitisnotset.json)
- `kubescape` **C-0289** · HIGH · manual · CIS cis-gke-v1.9.0:4.5.1; cis-v1.10.0:5.5.1; cis-v1.12.0:5.5.1 — Configure Image Provenance using ImagePolicyWebhook admission controller
  - _What:_ Configure Image Provenance for your deployment.
  - _Fix:_ Follow the Kubernetes documentation and setup image provenance.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0289-configureimageprovenanceusingimagepolicywebhookadmissioncontroller.json)
- `prowler` **apiserver_namespace_lifecycle_plugin** · HIGH — API server pod has NamespaceLifecycle admission control plugin enabled
  - _What:_ **Kubernetes API server** has the `NamespaceLifecycle` admission controller active and not disabled, enforcing namespace lifecycle rules by rejecting objects targeting **non-existent** or **terminating** namespaces and protecting system namespaces from deletion.
  - _Fix:_ Ensure `NamespaceLifecycle` remains enabled to enforce namespace governance. Apply **least privilege** for namespace creation/deletion, and use **separation of duties** for approvals. Monitor deletions and remediate stuck finalizers so cleanup completes. Combine with RBAC and audit logs for …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_namespace_lifecycle_plugin/apiserver_namespace_lifecycle_plugin.metadata.json)
- `prowler` **apiserver_service_account_plugin** · HIGH — API server pod has ServiceAccount admission control plugin enabled
  - _What:_ **Kubernetes API server** includes the **ServiceAccount admission controller** (`ServiceAccount`)-enabled via `--enable-admission-plugins` and not listed in `--disable-admission-plugins`. It applies service account-related defaults and policies to Pods, such as assigning a service account and governing secret references.
  - _Fix:_ Enable and keep the `ServiceAccount` admission controller active to enforce identity and secret policies. - Apply **least privilege**: restrict secrets on each service account - Disable token automount where not needed (`automountServiceAccountToken=false`) - Isolate secrets by namespace and …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_service_account_plugin/apiserver_service_account_plugin.metadata.json)
- `kubescape` **C-0039** · MEDIUM — Validate admission controller (mutating)
  - _What:_ Attackers may use mutating webhooks to intercept and modify all the resources in the cluster. This control lists all mutating webhook configurations that must be verified.
  - _Fix:_ Ensure all the webhooks are necessary. Use exception mechanism to prevent repititive notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0039-maliciousadmissioncontrollermutating.json)
- `kubescape` **C-0121** · MEDIUM · CIS cis-v1.10.0:1.2.9; cis-v1.12.0:1.2.9 — Ensure that the admission control plugin EventRateLimit is set
  - _What:_ Limit the rate at which the API server accepts requests.
  - _Fix:_ Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` and set the below parameters. ``` --enable-admission-plugins=...,EventRateLimit,... …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0121-ensurethattheadmissioncontrolplugineventratelimitisset.json)
- `prowler` **apiserver_event_rate_limit** · MEDIUM — API server pod has the EventRateLimit admission control plugin enabled
  - _What:_ **Kubernetes API server** includes `EventRateLimit` among its enabled admission plugins, applying rate controls to Kubernetes `Event` objects during admission
  - _Fix:_ Use the `EventRateLimit` admission plugin with conservative, workload-aware thresholds (global, per-namespace, per-user) to cap Event throughput. Apply **defense in depth**: monitor Event volume, alert on spikes, tame noisy emitters, and uphold **least privilege** to preserve API capacity. Steps: …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_event_rate_limit/apiserver_event_rate_limit.metadata.json)
- `kubescape` **C-0036** · LOW — Validate admission controller (validating)
  - _What:_ Attackers can use validating webhooks to intercept and discover all the resources in the cluster. This control lists all the validating webhook configurations that must be verified.
  - _Fix:_ Ensure all the webhooks are necessary. Use exception mechanism to prevent repititive notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0036-maliciousadmissioncontrollervalidating.json)
- `kubescape` **C-0125** · LOW · CIS cis-v1.10.0:1.2.12; cis-v1.12.0:1.2.12 — Ensure that the admission control plugin ServiceAccount is set
  - _What:_ Automate service accounts management.
  - _Fix:_ Follow the documentation and create `ServiceAccount` objects as per your environment. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and ensure that the `--disable-admission-plugins` parameter is set to a value that does not …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0125-ensurethattheadmissioncontrolpluginserviceaccountisset.json)
- `kubescape` **C-0126** · LOW · CIS cis-v1.10.0:1.2.13; cis-v1.12.0:1.2.13 — Ensure that the admission control plugin NamespaceLifecycle is set
  - _What:_ Reject creating objects in a namespace that is undergoing termination.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--disable-admission-plugins` parameter to ensure it does not include `NamespaceLifecycle`.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0126-ensurethattheadmissioncontrolpluginnamespacelifecycleisset.json)
- `trivy` **KCV-0010** · LOW — Ensure that the admission control plugin EventRateLimit is set
  - _What:_ [API server] Limit the rate at which the API server accepts requests.
  - _Fix:_ Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_event_rate_limit_plugin.rego)
- `trivy` **KCV-0011** · LOW — Ensure that the admission control plugin AlwaysAdmit is not set
  - _What:_ [API server] Do not allow all requests.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --enable-admission- plugins parameter, or set it to a value that does not include AlwaysAdmit.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_always_admit_plugin.rego)
- `trivy` **KCV-0014** · LOW — Ensure that the admission control plugin ServiceAccount is set
  - _What:_ [API server] Automate service accounts management.
  - _Fix:_ Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is set to a value that does not include …
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_service_account_plugin.rego)
- `trivy` **KCV-0015** · LOW — Ensure that the admission control plugin NamespaceLifecycle is set
  - _What:_ [API server] Reject creating objects in a namespace that is undergoing termination.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_namespace_lifecycle_plugin.rego)
- `checkov` **CKV_K8S_78** — Ensure that the admission control plugin EventRateLimit is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAdmissionControlEventRateLimit.py)
- `checkov` **CKV_K8S_79** — Ensure that the admission control plugin AlwaysAdmit is not set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAdmissionControlAlwaysAdmit.py)
- `checkov` **CKV_K8S_82** — Ensure that the admission control plugin ServiceAccount is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountPlugin.py)
- `checkov` **CKV_K8S_83** — Ensure that the admission control plugin NamespaceLifecycle is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerNamespaceLifecyclePlugin.py)
- `checkov` **CKV_K8S_85** — Ensure that the admission control plugin NodeRestriction is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerNodeRestrictionPlugin.py)
- `kube-bench` **1.2.10** · CIS cis-1.11:1.2.10 — Ensure that the admission control plugin AlwaysAdmit is not set
  - _What:_ [API Server] Ensure that the admission control plugin AlwaysAdmit is not set
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and either remove the --enable-admission-plugins parameter, or set it to a value that does not include AlwaysAdmit.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.12** · CIS cis-1.11:1.2.12 — Ensure that the admission control plugin ServiceAccount is set
  - _What:_ [API Server] Ensure that the admission control plugin ServiceAccount is set
  - _Fix:_ Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file $apiserverconf on the control plane node and ensure that the --disable-admission-plugins parameter is set to a value that does not include ServiceAccount.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.13** · CIS cis-1.11:1.2.13 — Ensure that the admission control plugin NamespaceLifecycle is set
  - _What:_ [API Server] Ensure that the admission control plugin NamespaceLifecycle is set
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.14** · CIS cis-1.11:1.2.14 — Ensure that the admission control plugin NodeRestriction is set
  - _What:_ [API Server] Ensure that the admission control plugin NodeRestriction is set
  - _Fix:_ Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction. …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.9** · manual · CIS cis-1.11:1.2.9 — Ensure that the admission control plugin EventRateLimit is set
  - _What:_ [API Server] Ensure that the admission control plugin EventRateLimit is set
  - _Fix:_ Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file $apiserverconf and set the below parameters. --enable-admission-plugins=...,EventRateLimit,... --admission-control-config-file=<path/to/configuration/file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **5.5.1** · manual · CIS cis-1.11:5.5.1 — Configure Image Provenance using ImagePolicyWebhook admission controller
  - _What:_ [Extensible Admission Control] Configure Image Provenance using ImagePolicyWebhook admission controller
  - _Fix:_ Follow the Kubernetes documentation and setup image provenance.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### Bind address / insecure port  
_2 rules · tools: checkov, kubescape_

- `kubescape` **C-0005** · CRITICAL — API server insecure port is enabled
  - _What:_ Kubernetes control plane API is running with non-secure port enabled which allows attackers to gain unprotected access to the cluster.
  - _Fix:_ Set the insecure-port flag of the API server to zero.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0005-apiserverinsecureportisenabled.json)
- `checkov` **CKV_K8S_86** — Ensure that the --insecure-bind-address argument is not set
  - _What:_ [API server] Ensure that the --insecure-bind-address argument is not set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerInsecureBindAddress.py)

### Encryption at rest / KMS  
_2 rules · tools: kube-bench_

- `kube-bench` **1.2.27** · manual · CIS cis-1.11:1.2.27 — Ensure that the --encryption-provider-config argument is set as appropriate
  - _What:_ [API Server] Ensure that the --encryption-provider-config argument is set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the --encryption-provider-config parameter to the path of that file. For example, …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.28** · manual · CIS cis-1.11:1.2.28 — Ensure that encryption providers are appropriately configured
  - _What:_ [API Server] Ensure that encryption providers are appropriately configured
  - _Fix:_ Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, choose aescbc, kms or secretbox as the encryption provider.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### File permissions / ownership  
_2 rules · tools: kyverno, trivy_

- `trivy` **KSV-0048** · MEDIUM — Manage Kubernetes workloads and pods
  - _What:_ Depending on the policies enforced by the admission controller, this permission ranges from the ability to steal compute (crypto) by running workloads or allowing for creating workloads that escape to the node as root and escalation to cluster-admin.
  - _Fix:_ Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/allowing_to_update_a_malicious_pod.rego)
- `kyverno` **check-subjectaccessreview** — Check SubjectAccessReview
  - _What:_ In some cases a validation check for one type of resource may need to take into consideration the requesting user's permissions on a different type of resource. Rather than parsing through all Roles and/or ClusterRoles to check if these permissions are held, Kyverno can perform a SubjectAccessReview request to the Kubernetes API server and have it figure out those permissions. This policy …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-subjectaccessreview/check-subjectaccessreview.yaml)

### Image pull policy  
_5 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `kubescape` **C-0123** · MEDIUM · CIS cis-v1.10.0:1.2.11; cis-v1.12.0:1.2.11 — Ensure that the admission control plugin AlwaysPullImages is set
  - _What:_ Always pull images.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--enable-admission-plugins` parameter to include `AlwaysPullImages`. ``` --enable-admission-plugins=...,AlwaysPullImages,... ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0123-ensurethattheadmissioncontrolpluginalwayspullimagesisset.json)
- `prowler` **apiserver_always_pull_images_plugin** · MEDIUM — API server pod has AlwaysPullImages admission control plugin enabled
  - _What:_ **Kubernetes API server** admission configuration includes **AlwaysPullImages**, which mutates new Pods to set `imagePullPolicy=Always` so container images are fetched from the registry at startup using the pod's credentials.
  - _Fix:_ Enable `AlwaysPullImages` on the API server. Apply defense in depth: restrict pulls to trusted registries, enforce least-privilege image pull secrets, sign and scan images, and prefer immutable digests to prevent drift and ensure verified content. Steps: 1. SSH to a control-plane node 2. Edit …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_always_pull_images_plugin/apiserver_always_pull_images_plugin.metadata.json)
- `trivy` **KCV-0012** · LOW — Ensure that the admission control plugin AlwaysPullImages is set
  - _What:_ [API server] Always pull images.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include AlwaysPullImages.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_always_pull_images_plugin.rego)
- `checkov` **CKV_K8S_80** — Ensure that the admission control plugin AlwaysPullImages is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerAlwaysPullImagesPlugin.py)
- `kube-bench` **1.2.11** · manual · CIS cis-1.11:1.2.11 — Ensure that the admission control plugin AlwaysPullImages is set
  - _What:_ [API Server] Ensure that the admission control plugin AlwaysPullImages is set
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --enable-admission-plugins parameter to include AlwaysPullImages. --enable-admission-plugins=...,AlwaysPullImages,...
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### NodePort / LoadBalancer / external exposure  
_5 rules · tools: kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_deny_service_external_ips** · HIGH — API server pod has DenyServiceExternalIPs admission controller enabled
  - _What:_ **Kubernetes API server** with **DenyServiceExternalIPs** rejects net-new use of `Service.spec.externalIPs` and additions to that field on existing Services; existing values can only be removed.
  - _Fix:_ Enable **DenyServiceExternalIPs** to block net-new `externalIPs` usage. Apply **least privilege** RBAC on Services (including status updates), require change control for exposure, and favor controlled **Ingress/LoadBalancer** patterns. Use admission policies to tightly allow approved exceptions as …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_deny_service_external_ips/apiserver_deny_service_external_ips.metadata.json)
- `kubescape` **C-0115** · MEDIUM — Ensure that the API Server --DenyServiceExternalIPs is not set
  - _What:_ This admission controller rejects all net-new usage of the Service field externalIPs.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and remove the `--DenyServiceExternalIPs'parameter or The Kubernetes API server flag disable-admission-plugins takes a comma-delimited list of admission control plugins to be disabled, …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0115-ensurethattheapiserverdenyserviceexternalipsisnotset.json)
- `kubescape` **C-0283** · MEDIUM · CIS cis-v1.10.0:1.2.3; cis-v1.12.0:1.2.3 — Ensure that the API Server --DenyServiceExternalIPs is set
  - _What:_ This admission controller rejects all net-new usage of the Service field externalIPs.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and add the `--enable-admission-plugins=DenyServiceExternalIPs` parameter or The Kubernetes API server flag disable-admission-plugins takes a comma-delimited list of admission control …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0283-ensurethattheapiserverdenyserviceexternalipsisset.json)
- `trivy` **KCV-0003** · LOW — Ensure that the --DenyServiceExternalIPs is not set
  - _What:_ [API server] This admission controller rejects all net-new usage of the Service field externalIPs.
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and remove the `DenyServiceExternalIPs` from enabled admission plugins.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_deny_service_external_ips_plugin.rego)
- `kube-bench` **1.2.3** · manual · CIS cis-1.11:1.2.3 — Ensure that the --DenyServiceExternalIPs is set
  - _What:_ [API Server] Ensure that the --DenyServiceExternalIPs is set
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and add the `DenyServiceExternalIPs` plugin to the enabled admission plugins, as such --enable-admission-plugin=DenyServiceExternalIPs.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Pod Security Standards / PSA / PSP  
_6 rules · tools: checkov, kubescape, prowler, trivy_

- `prowler` **apiserver_security_context_deny_plugin** · HIGH — API server pod uses PodSecurityPolicy or has the SecurityContextDeny admission plugin enabled
  - _What:_ **Kubernetes API server** admission configuration is reviewed for `PodSecurityPolicy` or `SecurityContextDeny`, indicating whether pods using high-risk `securityContext` fields (privileged, host access, extra capabilities) would be blocked during admission.
  - _Fix:_ Apply defense-in-depth at admission: - Prefer **Pod Security Admission** with `restricted` policies - *For legacy clusters*, enable `SecurityContextDeny` or an equivalent policy engine - Enforce **least privilege**: set `allowPrivilegeEscalation=false`, drop unnecessary capabilities, and avoid …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_security_context_deny_plugin/apiserver_security_context_deny_plugin.metadata.json)
- `kubescape` **C-0124** · MEDIUM — Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used
  - _What:_ The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--enable-admission-plugins` parameter to include `SecurityContextDeny`, unless `PodSecurityPolicy` is already in place. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0124-ensurethattheadmissioncontrolpluginsecuritycontextdenyissetifpodsecuritypolicyisnotused.json)
- `kubescape` **C-0192** · MEDIUM · CIS cis-gke-v1.9.0:4.2.1; cis-v1.10.0:5.2.1; cis-v1.12.0:5.2.1 — Ensure that the cluster has at least one active policy control mechanism in place
  - _What:_ Every Kubernetes cluster should have at least one policy control mechanism in place to enforce the other requirements in this section. This could be the in-built Pod Security Admission controller, or a third party policy control system.
  - _Fix:_ Ensure that either Pod Security Admission or an external policy control system is in place for every namespace which contains user workloads.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0192-ensurethattheclusterhasatleastoneactivepolicycontrolmechanisminplace.json)
- `trivy` **KCV-0013** · LOW · CIS k8s-cis-1.23:1.2.13; rke2-cis-1.24:1.2.13 — Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used
  - _What:_ [API server] The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_security_context_deny_plugin.rego)
- `checkov` **CKV_K8S_81** — Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerSecurityContextDenyPlugin.py)
- `checkov` **CKV_K8S_84** — Ensure that the admission control plugin PodSecurityPolicy is set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerPodSecurityPolicyPlugin.py)

### Profiling endpoints  
_7 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_disable_profiling** · MEDIUM — API server pod has profiling disabled (--profiling=false)
  - _What:_ **Kubernetes API server** runtime profiling is controlled by the `--profiling` flag. The evaluation inspects API server container arguments to confirm `--profiling=false` and that profiling endpoints (such as `/debug/pprof`) are not enabled.
  - _Fix:_ Keep API server profiling disabled by default. *If diagnostics are required*, enable it briefly in a controlled, isolated environment. Apply **least privilege** to debug access, restrict exposure via network controls, and audit usage. Use **defense in depth** and separation of duties for any …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_disable_profiling/apiserver_disable_profiling.metadata.json)
- `prowler` **scheduler_profiling** · MEDIUM — Scheduler pod has profiling disabled
  - _What:_ **Kubernetes Scheduler** profiling configuration, specifically whether scheduler containers run with `--profiling=false` to keep the profiling API disabled.
  - _Fix:_ Disable by default: set `--profiling=false` on the Scheduler. If profiling is required, enable it only temporarily, restrict access with **network policies**, bind to loopback, and log/monitor usage. Apply **least privilege** and **defense in depth** to limit exposure. Steps: 1. SSH to the …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/scheduler/scheduler_profiling/scheduler_profiling.metadata.json)
- `kubescape` **C-0129** · LOW · CIS cis-v1.10.0:1.2.15; cis-v1.12.0:1.2.15 — Ensure that the API Server --profiling argument is set to false
  - _What:_ Disable profiling, if not needed.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the below parameter. ``` --profiling=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0129-ensurethattheapiserverprofilingargumentissettofalse.json)
- `kubescape` **C-0151** · LOW · CIS cis-v1.10.0:1.4.1; cis-v1.12.0:1.4.1 — Ensure that the Scheduler --profiling argument is set to false
  - _What:_ Disable profiling, if not needed.
  - _Fix:_ Edit the Scheduler pod specification file `/etc/kubernetes/manifests/kube-scheduler.yaml` file on the Control Plane node and set the below parameter. ``` --profiling=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0151-ensurethattheschedulerprofilingargumentissettofalse.json)
- `trivy` **KCV-0018** · LOW — Ensure that the --profiling argument is set to false
  - _What:_ [API server] Disable profiling, if not needed.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_profiling.rego)
- `checkov` **CKV_K8S_90** — Ensure that the --profiling argument is set to false
  - _What:_ [API server] Ensure that the --profiling argument is set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerProfiling.py)
- `kube-bench` **1.2.15** · CIS cis-1.11:1.2.15 — Ensure that the --profiling argument is set to false
  - _What:_ [API Server] Ensure that the --profiling argument is set to false
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the below parameter. --profiling=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### ServiceAccount token automount  
_5 rules · tools: kubescape, kyverno, prowler_

- `prowler` **apiserver_service_account_key_file_set** · HIGH — API server pod has --service-account-key-file configured
  - _What:_ **Kubernetes API server** uses `--service-account-key-file` to supply the public key(s) for validating **service account tokens**. Detection looks for API server containers that lack this flag.
  - _Fix:_ Use a dedicated key pair for **service accounts**: - Configure `--service-account-key-file` with public keys for validation - Keep signing and serving keys separate (*least privilege*) - Enforce scheduled key rotation and maintain multiple active keys for **defense in depth** Steps: 1. SSH to the …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_service_account_key_file_set/apiserver_service_account_key_file_set.metadata.json)
- `prowler` **apiserver_service_account_lookup_true** · HIGH — API server pod has --service-account-lookup set to true
  - _What:_ Kubernetes API server has **service account lookup** enabled via `--service-account-lookup=true`, validating presented service account tokens against currently existing ServiceAccounts during authentication.
  - _Fix:_ Enable `--service-account-lookup=true` so token validity depends on the ServiceAccount's current state. Apply **least privilege** to ServiceAccounts, favor short-lived tokens, and promptly remove unused accounts and secrets. Combine with strict **RBAC** and auditing for **defense in depth**. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_service_account_lookup_true/apiserver_service_account_lookup_true.metadata.json)
- `kubescape` **C-0190** · MEDIUM · CIS cis-aks-t1.2.0:4.1.6; cis-aks-t1.8.0:4.1.6; cis-eks-t1.7.0:4.1.6; cis-eks-t1.8.0:4.1.6; cis-gke-v1.9.0:4.1.5; cis-v1.10.0:5.1.6; cis-v1.12.0:5.1.6 — Ensure that Service Account Tokens are only mounted where necessary
  - _What:_ Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server
  - _Fix:_ Modify the definition of pods and service accounts which do not need to mount service account tokens to disable it.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0190-ensurethatserviceaccounttokensareonlymountedwherenecessary.json)
- `kubescape` **C-0287** · MEDIUM · manual · CIS cis-v1.10.0:3.1.2; cis-v1.12.0:3.1.2 — Service account token authentication should not be used for users
  - _What:_ Kubernetes provides service account tokens which are intended for use by workloads running in the Kubernetes cluster, for authentication to the API server. These tokens are not designed for use by end-users and do not provide for features such as revocation or expiry, making them insecure. A newer version of the feature (Bound service account token volumes) does introduce expiry but still does …
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of service account tokens.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0287-serviceaccounttokenauthenticationshouldnotbeusedforusers.json)
- `kyverno` **restrict-sa-automount-sa-token** · MEDIUM — Restrict Auto-Mount of Service Account Tokens in Service Account
  - _What:_ Kubernetes automatically mounts ServiceAccount credentials in each ServiceAccount. The ServiceAccount may be assigned roles allowing Pods to access API resources. Blocking this ability is an extension of the least privilege best practice and should be followed if Pods do not need to speak to the API server to function. This policy ensures that mounting of these ServiceAccount tokens is blocked.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-sa-automount-sa-token/restrict-sa-automount-sa-token.yaml)

### TLS / certificates / ciphers  
_14 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `kubescape` **C-0138** · HIGH · CIS cis-v1.10.0:1.2.24; cis-v1.12.0:1.2.24 — Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ Setup TLS connection on the API server.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the TLS certificate and private key file parameters. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0138-ensurethattheapiservertlscertfileandtlsprivatekeyfileargumentsaresetasappropriate.json)
- `kubescape` **C-0139** · HIGH · CIS cis-v1.10.0:1.2.25; cis-v1.12.0:1.2.25 — Ensure that the API Server --client-ca-file argument is set as appropriate
  - _What:_ Setup TLS connection on the API server.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the client certificate authority file. ``` --client-ca-file=<path/to/client-ca-file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0139-ensurethattheapiserverclientcafileargumentissetasappropriate.json)
- `prowler` **apiserver_client_ca_file_set** · HIGH — API server pod has the --client-ca-file argument set
  - _What:_ **Kubernetes API server** uses a configured **client CA** (`--client-ca-file`) to validate x509 client certificates presented for API authentication
  - _Fix:_ Establish a trusted **client CA** for the API server and require **certificate-based client authentication**. Combine with **RBAC** and **least privilege**, disable anonymous access, and enforce **key rotation** and auditing to provide **defense in depth**. Steps: 1. SSH to each control-plane node …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_client_ca_file_set/apiserver_client_ca_file_set.metadata.json)
- `prowler` **apiserver_tls_config** · HIGH — API server pod has --tls-cert-file and --tls-private-key-file configured
  - _What:_ **Kubernetes API server** configuration is checked for explicit TLS settings via `--tls-cert-file` and `--tls-private-key-file`. The presence of both flags indicates HTTPS is configured with a specified certificate and private key for client connections.
  - _Fix:_ Configure the API server to use **TLS** with a valid certificate and key via `--tls-cert-file` and `--tls-private-key-file`. Use a trusted CA with correct SANs, restrict network access to the endpoint, and automate certificate rotation and expiry monitoring to uphold **defense in depth** and …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_tls_config/apiserver_tls_config.metadata.json)
- `kubescape` **C-0143** · MEDIUM — Ensure that the API Server only makes use of Strong Cryptographic Ciphers
  - _What:_ Ensure that the API server is configured to only use strong cryptographic ciphers.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter. ``` --tls-cipher-suites=TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0143-ensurethattheapiserveronlymakesuseofstrongcryptographicciphers.json)
- `kubescape` **C-0277** · MEDIUM · CIS cis-v1.10.0:1.2.29; cis-v1.12.0:1.2.29 — Ensure that the API Server only makes use of Strong Cryptographic Ciphers
  - _What:_ Ensure that the API server is configured to only use strong cryptographic ciphers.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter. ``` --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0277-ensurethattheapiserveronlymakesuseofstrongcryptographicciphers-new.json)
- `prowler` **apiserver_strong_ciphers_only** · MEDIUM — API Server pod uses only strong cryptographic TLS cipher suites
  - _What:_ **Kubernetes API server** restricts TLS to **strong cipher suites** by configuring `--tls-cipher-suites` to only modern values such as `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`
  - _Fix:_ Limit ciphers to modern AEAD suites and remove legacy entries in `--tls-cipher-suites`. - Enforce a high `--tls-min-version` (prefer `VersionTLS13`). - Periodically review crypto policy and rotate keys. - Apply **defense in depth**: restrict API exposure and require strong client auth. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_strong_ciphers_only/apiserver_strong_ciphers_only.metadata.json)
- `trivy` **KCV-0027** · LOW — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ [API server] Setup TLS connection on the API server.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the TLS certificate and private key file parameters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_tls_cert_file_and_private_key_file.rego)
- `trivy` **KCV-0028** · LOW — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ [API server] Setup TLS connection on the API server.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the client certificate authority file.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_client_ca_file.rego)
- `checkov` **CKV_K8S_100** — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ [API server] Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerTlsCertAndKey.py)
- `checkov` **CKV_K8S_105** — Ensure that the API Server only makes use of Strong Cryptographic Ciphers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerStrongCryptographicCiphers.py)
- `kube-bench` **1.2.24** · CIS cis-1.11:1.2.24 — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ [API Server] Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the TLS certificate and private key file parameters. --tls-cert-file=<path/to/tls-certificate-file> …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.25** · CIS cis-1.11:1.2.25 — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ [API Server] Ensure that the --client-ca-file argument is set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the client certificate authority file. --client-ca-file=<path/to/client-ca-file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.29** · manual · CIS cis-1.11:1.2.29 — Ensure that the API Server only makes use of Strong Cryptographic Ciphers
  - _What:_ [API Server] Ensure that the API Server only makes use of Strong Cryptographic Ciphers
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the control plane node and set the below parameter. --tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256, …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Token / basic auth files  
_6 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `kubescape` **C-0114** · HIGH · CIS cis-v1.10.0:1.2.2; cis-v1.12.0:1.2.2 — Ensure that the API Server --token-auth-file parameter is not set
  - _What:_ Do not use token based authentication.
  - _Fix:_ Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and remove the `--token-auth-file=<filename>` parameter.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0114-ensurethattheapiservertokenauthfileparameterisnotset.json)
- `prowler` **apiserver_no_token_auth_file** · HIGH — API server pod does not have --token-auth-file enabled
  - _What:_ **Kubernetes API server** configuration is reviewed for use of **static token file authentication** by inspecting API server containers for the `--token-auth-file` argument
  - _Fix:_ Avoid **static token files**. Prefer **client certificates**, **OIDC/webhook authenticators**, or **service accounts** with short-lived tokens. Apply **least privilege** with RBAC, enforce **rotation** and short expirations, and disable `--token-auth-file` to support **defense in depth** and rapid …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_no_token_auth_file/apiserver_no_token_auth_file.metadata.json)
- `trivy` **KCV-0002** · LOW — Ensure that the --token-auth-file parameter is not set
  - _What:_ [API server] Do not use token based authentication.
  - _Fix:_ Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_token_auth_file.rego)
- `checkov` **CKV_K8S_69** — Ensure that the --basic-auth-file argument is not set
  - _What:_ [API server] Ensure that the --basic-auth-file argument is not set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerBasicAuthFile.py)
- `checkov` **CKV_K8S_70** — Ensure that the --token-auth-file argument is not set
  - _What:_ [API server] Ensure that the --token-auth-file argument is not set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerTokenAuthFile.py)
- `kube-bench` **1.2.2** · CIS cis-1.11:1.2.2 — Ensure that the --token-auth-file parameter is not set
  - _What:_ [API Server] Ensure that the --token-auth-file parameter is not set
  - _Fix:_ Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file $apiserverconf on the control plane node and remove the --token-auth-file=<filename> parameter.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### procMount  
_1 rules · tools: kyverno_

- `kyverno` **disallow-proc-mount** · MEDIUM — Disallow procMount
  - _What:_ The default /proc masks are set up to reduce attack surface and should be required. This policy ensures nothing but the default procMount can be specified. Note that in order for users to deviate from the `Default` procMount requires setting a feature gate at the API server.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-proc-mount/disallow-proc-mount.yaml)

### Other  
_15 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_auth_mode_include_rbac** · HIGH — API server pod authorization mode includes RBAC
  - _What:_ **Kubernetes API server** authorization configuration includes the **RBAC authorizer** in the enabled modes, i.e., `RBAC` appears in the authorizer chain.
  - _Fix:_ Adopt **RBAC** as the primary authorizer and avoid permissive modes like `AlwaysAllow` or legacy `ABAC`. Enforce **least privilege** with narrowly scoped roles and bindings, apply **separation of duties**, and monitor authorization activity for **defense in depth**. Steps: 1. SSH to each …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_auth_mode_include_rbac/apiserver_auth_mode_include_rbac.metadata.json)
- `kubescape` **C-0053** · MEDIUM — Access container service account
  - _What:_ Attackers who obtain access to a pod can use its SA token to communicate with KubeAPI server. All pods with SA token mounted (if such token has a Role or a ClusterRole binding) are considerred potentially dangerous.
  - _Fix:_ Verify that RBAC is enabled. Follow the least privilege principle and ensure that only necessary pods have SA token mounted into them.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0053-accesscontainerserviceaccount.json)
- `kubescape` **C-0134** · MEDIUM · CIS cis-v1.10.0:1.2.20; cis-v1.12.0:1.2.20 — Ensure that the API Server --request-timeout argument is set as appropriate
  - _What:_ Set global request timeout for API server requests as appropriate.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` and set the below parameter as appropriate and if needed. For example, ``` --request-timeout=300s ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0134-ensurethattheapiserverrequesttimeoutargumentissetasappropriate.json)
- `kubescape` **C-0135** · MEDIUM · CIS cis-v1.10.0:1.2.21; cis-v1.12.0:1.2.21 — Ensure that the API Server --service-account-lookup argument is set to true
  - _What:_ Validate service account before validating token.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the below parameter. ``` --service-account-lookup=true ``` Alternatively, you can delete the `--service-account-lookup` parameter from this file so that the default takes …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0135-ensurethattheapiserverserviceaccountlookupargumentissettotrue.json)
- `kubescape` **C-0136** · MEDIUM · CIS cis-v1.10.0:1.2.22; cis-v1.12.0:1.2.22 — Ensure that the API Server --service-account-key-file argument is set as appropriate
  - _What:_ Explicitly set a service account public key file for service accounts on the apiserver.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--service-account-key-file` parameter to the public key file for service accounts: ``` --service-account-key-file=<filename> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0136-ensurethattheapiserverserviceaccountkeyfileargumentissetasappropriate.json)
- `prowler` **apiserver_request_timeout_set** · MEDIUM — API server pod has --request-timeout configured
  - _What:_ **Kubernetes API server** has a global request timeout configured via `--request-timeout`. The presence of that flag on API server containers is assessed.
  - _Fix:_ Set `--request-timeout` to a bounded value aligned to typical non-watch calls; *when needed*, tune `--min-request-timeout` for watches. Combine with **priority and fairness**, rate limiting, and load testing to prevent starvation. Monitor latency and errors to adjust. Apply **defense in depth**. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_request_timeout_set/apiserver_request_timeout_set.metadata.json)
- `trivy` **KCV-0024** · LOW — Ensure that the --service-account-lookup argument is set to true
  - _What:_ [API server] Validate service account before validating token.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_service_account_lookup.rego)
- `trivy` **KCV-0025** · LOW — Ensure that the --service-account-key-file argument is set as appropriate
  - _What:_ [API server] Explicitly set a service account public key file for service accounts on the apiserver.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --service-account-key-file parameter to the public key file for service accounts.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_service_account_key_file.rego)
- `checkov` **CKV_K8S_95** — Ensure that the --request-timeout argument is set as appropriate
  - _What:_ [API server] Ensure that the --request-timeout argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerRequestTimeout.py)
- `checkov` **CKV_K8S_96** — Ensure that the --service-account-lookup argument is set to true
  - _What:_ [API server] Ensure that the --service-account-lookup argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountLookup.py)
- `checkov` **CKV_K8S_97** — Ensure that the --service-account-key-file argument is set as appropriate
  - _What:_ [API server] Ensure that the --service-account-key-file argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountKeyFile.py)
- `kube-bench` **1.2.20** · manual · CIS cis-1.11:1.2.20 — Ensure that the --request-timeout argument is set as appropriate
  - _What:_ [API Server] Ensure that the --request-timeout argument is set as appropriate
  - _Fix:_ Edit the API server pod specification file $apiserverconf and set the below parameter as appropriate and if needed. For example, --request-timeout=300s
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.21** · CIS cis-1.11:1.2.21 — Ensure that the --service-account-lookup argument is set to true
  - _What:_ [API Server] Ensure that the --service-account-lookup argument is set to true
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the below parameter. --service-account-lookup=true Alternatively, you can delete the --service-account-lookup parameter from this file so that the default takes effect.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.22** · CIS cis-1.11:1.2.22 — Ensure that the --service-account-key-file argument is set as appropriate
  - _What:_ [API Server] Ensure that the --service-account-key-file argument is set as appropriate
  - _Fix:_ Edit the API server pod specification file $apiserverconf on the control plane node and set the --service-account-key-file parameter to the public key file for service accounts. For example, --service-account-key-file=<filename>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.30** · CIS cis-1.11:1.2.30 — Ensure that the --service-account-extend-token-expiration parameter is set to false
  - _What:_ [API Server] Ensure that the --service-account-extend-token-expiration parameter is set to false
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --service-account-extend-token-expiration parameter to false. `--service-account-extend-token-expiration=false` By default, this parameter is set to true.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)


## Control plane: controller manager & scheduler

### Bind address / insecure port  
_8 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **controllermanager_bind_address** · HIGH — Controller Manager pod is bound to the loopback address 127.0.0.1
  - _What:_ **Kubernetes controller manager** uses the **loopback bind address** `127.0.0.1` via `--bind-address` or `--address`, keeping its health, metrics, and debug endpoints reachable only from the host
  - _Fix:_ Bind to `127.0.0.1` and apply **defense in depth**: - Prefer local-only endpoints; avoid `0.0.0.0` - Use **TLS** and authentication if exposure is unavoidable - Enforce **network segmentation** for control-plane access - Disable profiling when not needed; apply **least privilege** for telemetry …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_bind_address/controllermanager_bind_address.metadata.json)
- `kubescape` **C-0150** · MEDIUM · CIS cis-v1.10.0:1.3.7; cis-v1.12.0:1.3.7 — Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1
  - _What:_ Do not bind the Controller Manager service to non-loopback insecure addresses.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and ensure the correct value for the `--bind-address` parameter
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0150-ensurethatthecontrollermanagerbindaddressargumentissetto127001.json)
- `trivy` **KCV-0039** · LOW — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [controller manager] Do not bind the scheduler service to non-loopback insecure addresses.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_bind_address.rego)
- `trivy` **KCV-0041** · LOW — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [scheduler] Do not bind the scheduler service to non-loopback insecure addresses.
  - _Fix:_ Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_bind_address.rego)
- `checkov` **CKV_K8S_113** — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [controller manager] Ensure that the --bind-address argument is set to 127.0.0.1
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ControllerManagerBindAddress.py)
- `checkov` **CKV_K8S_115** — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [scheduler] Ensure that the --bind-address argument is set to 127.0.0.1
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/SchedulerBindAddress.py)
- `kube-bench` **1.3.7** · CIS cis-1.11:1.3.7 — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [Controller Manager] Ensure that the --bind-address argument is set to 127.0.0.1
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and ensure the correct value for the --bind-address parameter
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.4.2** · CIS cis-1.11:1.4.2 — Ensure that the --bind-address argument is set to 127.0.0.1
  - _What:_ [Scheduler] Ensure that the --bind-address argument is set to 127.0.0.1
  - _Fix:_ Edit the Scheduler pod specification file $schedulerconf on the control plane node and ensure the correct value for the --bind-address parameter
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Profiling endpoints  
_8 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **controllermanager_disable_profiling** · MEDIUM — Controller Manager pod has --profiling=false configured
  - _What:_ **Kubernetes Controller Manager** is evaluated for the `--profiling` argument. `--profiling=false` disables runtime profiling; absence or a different value means profiling is enabled.
  - _Fix:_ Set `--profiling=false` on the **controller manager** to remove debug endpoints. *If profiling is needed temporarily*: - Limit access using **least privilege** and network controls - Use isolated environments and monitor closely - Disable promptly to uphold **defense in depth** Steps: 1. SSH to …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_disable_profiling/controllermanager_disable_profiling.metadata.json)
- `kubescape` **C-0145** · LOW · CIS cis-v1.10.0:1.3.2; cis-v1.12.0:1.3.2 — Ensure that the Controller Manager --profiling argument is set to false
  - _What:_ Disable profiling, if not needed.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and set the below parameter. ``` --profiling=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0145-ensurethatthecontrollermanagerprofilingargumentissettofalse.json)
- `trivy` **KCV-0034** · LOW — Ensure that the --profiling argument is set to false
  - _What:_ [controller manager] Disable profiling, if not needed.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_profiling.rego)
- `trivy` **KCV-0040** · LOW — Ensure that the --profiling argument is set to false
  - _What:_ [scheduler] Disable profiling, if not needed.
  - _Fix:_ Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the Control Plane node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_profiling.rego)
- `checkov` **CKV_K8S_107** — Ensure that the --profiling argument is set to false
  - _What:_ [controller manager] Ensure that the --profiling argument is set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerBlockProfiles.py)
- `checkov` **CKV_K8S_114** — Ensure that the --profiling argument is set to false
  - _What:_ [scheduler] Ensure that the --profiling argument is set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/SchedulerProfiling.py)
- `kube-bench` **1.3.2** · CIS cis-1.11:1.3.2 — Ensure that the --profiling argument is set to false
  - _What:_ [Controller Manager] Ensure that the --profiling argument is set to false
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and set the below parameter. --profiling=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.4.1** · CIS cis-1.11:1.4.1 — Ensure that the --profiling argument is set to false
  - _What:_ [Scheduler] Ensure that the --profiling argument is set to false
  - _Fix:_ Edit the Scheduler pod specification file $schedulerconf file on the control plane node and set the below parameter. --profiling=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### ServiceAccount token automount  
_1 rules · tools: prowler_

- `prowler` **controllermanager_service_account_private_key_file** · HIGH — Controller Manager pod has the --service-account-private-key-file argument set
  - _What:_ **Kubernetes controller manager** uses a **service account signing key** configured via `--service-account-private-key-file`. The evaluation identifies whether this argument is present, indicating the component can sign service account tokens.
  - _Fix:_ Set a dedicated **signing key** using `--service-account-private-key-file`, or adopt an approved external signer. Apply **least privilege** to key access, enforce **regular rotation** and rollover, separate **signing/verification** duties, and prefer short-lived tokens with strict **RBAC**. Steps: …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_service_account_private_key_file/controllermanager_service_account_private_key_file.metadata.json)

### TLS / certificates / ciphers  
_5 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **controllermanager_root_ca_file_set** · CRITICAL — Controller Manager pod has --root-ca-file argument set
  - _What:_ **Kubernetes Controller Manager** uses `--root-ca-file` to reference a certificate bundle so pods get a `ca.crt` for validating the API server's TLS certificate.
  - _Fix:_ Set a trusted CA bundle via `--root-ca-file` on the controller manager to ensure verified TLS for in-cluster API calls. Use a cluster-controlled CA, rotate and monitor certificates, and keep the bundle aligned with the API server chain. Apply **defense in depth** and **least privilege** for …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_root_ca_file_set/controllermanager_root_ca_file_set.metadata.json)
- `kubescape` **C-0148** · HIGH · CIS cis-v1.10.0:1.3.5; cis-v1.12.0:1.3.5 — Ensure that the Controller Manager --root-ca-file argument is set as appropriate
  - _What:_ Allow pods to verify the API server's serving certificate before establishing connections.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and set the `--root-ca-file` parameter to the certificate bundle file`. ``` --root-ca-file=<path/to/file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0148-ensurethatthecontrollermanagerrootcafileargumentissetasappropriate.json)
- `trivy` **KCV-0037** · LOW — Ensure that the --root-ca-file argument is set as appropriate
  - _What:_ [controller manager] Allow pods to verify the API server's serving certificate before establishing connections.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --root-ca-file parameter to the certificate bundle file`.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_root_ca_file.rego)
- `checkov` **CKV_K8S_111** — Ensure that the --root-ca-file argument is set as appropriate
  - _What:_ [controller manager] Ensure that the --root-ca-file argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerRootCAFile.py)
- `kube-bench` **1.3.5** · CIS cis-1.11:1.3.5 — Ensure that the --root-ca-file argument is set as appropriate
  - _What:_ [Controller Manager] Ensure that the --root-ca-file argument is set as appropriate
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and set the --root-ca-file parameter to the certificate bundle file`. --root-ca-file=<path/to/file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Other  
_14 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **controllermanager_garbage_collection** · HIGH — Controller Manager pod does not use the default --terminated-pod-gc-threshold value
  - _What:_ **Kubernetes controller manager** terminated Pod garbage collection threshold is evaluated. The finding highlights use of the default `--terminated-pod-gc-threshold=12500` instead of a value tuned to cluster size and workload churn. The threshold controls when terminated Pods are automatically removed.
  - _Fix:_ Set a **lower, context-appropriate** `--terminated-pod-gc-threshold` to match cluster scale and pod churn, preserving control-plane capacity. Monitor garbage collection and control-plane metrics and adjust proactively. Use `ttlSecondsAfterFinished` for Jobs to minimize terminated Pods. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_garbage_collection/controllermanager_garbage_collection.metadata.json)
- `prowler` **controllermanager_service_account_credentials** · HIGH — Controller Manager pod has --use-service-account-credentials=true
  - _What:_ Evaluates whether the **Kubernetes controller manager** uses per-controller service account credentials via `--use-service-account-credentials=true`, meaning each controller runs with its own identity rather than a shared credential.
  - _Fix:_ Enable `--use-service-account-credentials=true` and enforce **least privilege**: assign a dedicated service account per controller with minimal RBAC, limit token scope/lifetime, and monitor controller actions. This upholds **separation of duties** and **defense in depth**. Steps: 1. SSH to each …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_service_account_credentials/controllermanager_service_account_credentials.metadata.json)
- `kubescape` **C-0144** · MEDIUM · CIS cis-v1.10.0:1.3.1; cis-v1.12.0:1.3.1 — Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate
  - _What:_ Activate garbage collector on pod termination, as appropriate.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and set the `--terminated-pod-gc-threshold` to an appropriate threshold, for example: ``` --terminated-pod-gc-threshold=10 ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0144-ensurethatthecontrollermanagerterminatedpodgcthresholdargumentissetasappropriate.json)
- `kubescape` **C-0146** · MEDIUM · CIS cis-v1.10.0:1.3.3; cis-v1.12.0:1.3.3 — Ensure that the Controller Manager --use-service-account-credentials argument is set to true
  - _What:_ Use individual service account credentials for each controller.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node to set the below parameter. ``` --use-service-account-credentials=true ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0146-ensurethatthecontrollermanageruseserviceaccountcredentialsargumentissettotrue.json)
- `kubescape` **C-0147** · MEDIUM · CIS cis-v1.10.0:1.3.4; cis-v1.12.0:1.3.4 — Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate
  - _What:_ Explicitly set a service account private key file for service accounts on the controller manager.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and set the `--service-account-private-key-file` parameter to the private key file for service accounts. ``` --service-account-private-key-file=<filename> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0147-ensurethatthecontrollermanagerserviceaccountprivatekeyfileargumentissetasappropriate.json)
- `trivy` **KCV-0033** · LOW — Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - _What:_ [controller manager] Activate garbage collector on pod termination, as appropriate.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --terminated-pod-gc-threshold to an appropriate threshold.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_terminated_pod_gc_threshold.rego)
- `trivy` **KCV-0035** · LOW — Ensure that the --use-service-account-credentials argument is set to true
  - _What:_ [controller manager] Use individual service account credentials for each controller.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node to set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_use_service_account_credentials.rego)
- `trivy` **KCV-0036** · LOW — Ensure that the --service-account-private-key-file argument is set as appropriate
  - _What:_ [controller manager] Explicitly set a service account private key file for service accounts on the controller manager.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --service-account-private-key-file parameter to the private key file for service accounts.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_service_account_private_key_file.rego)
- `checkov` **CKV_K8S_106** — Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - _What:_ [controller manager] Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerTerminatedPods.py)
- `checkov` **CKV_K8S_108** — Ensure that the --use-service-account-credentials argument is set to true
  - _What:_ [controller manager] Ensure that the --use-service-account-credentials argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerServiceAccountCredentials.py)
- `checkov` **CKV_K8S_110** — Ensure that the --service-account-private-key-file argument is set as appropriate
  - _What:_ [controller manager] Ensure that the --service-account-private-key-file argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerServiceAccountPrivateKeyFile.py)
- `kube-bench` **1.3.1** · manual · CIS cis-1.11:1.3.1 — Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - _What:_ [Controller Manager] Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and set the --terminated-pod-gc-threshold to an appropriate threshold, for example, --terminated-pod-gc-threshold=10
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.3.3** · CIS cis-1.11:1.3.3 — Ensure that the --use-service-account-credentials argument is set to true
  - _What:_ [Controller Manager] Ensure that the --use-service-account-credentials argument is set to true
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node to set the below parameter. --use-service-account-credentials=true
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.3.4** · CIS cis-1.11:1.3.4 — Ensure that the --service-account-private-key-file argument is set as appropriate
  - _What:_ [Controller Manager] Ensure that the --service-account-private-key-file argument is set as appropriate
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and set the --service-account-private-key-file parameter to the private key file for service accounts. --service-account-private-key-file=<filename>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)


## General / other

### Root group / fsGroup  
_1 rules · tools: trivy_

- `trivy` **KSV-0021** · LOW — Runs with GID <= 10000
  - _What:_ Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.
  - _Fix:_ Set 'containers[].securityContext.runAsGroup' to an integer > 10000.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runs_with_GID_le_10000.rego)

### Run as non-root user  
_1 rules · tools: trivy_

- `trivy` **KSV-0020** · LOW — Runs with UID <= 10000
  - _What:_ Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.
  - _Fix:_ Set 'containers[].securityContext.runAsUser' to an integer > 10000.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runs_with_UID_le_10000.rego)

### Other  
_3 rules · tools: kube-linter, kubescape_

- `kubescape` **C-0295** · LOW — Duplicate environment variable
  - _What:_ A container with duplicate environment variable names can behave unexpectedly because later values override earlier values. Duplicate entries usually indicate configuration drift or copy-paste mistakes.
  - _Fix:_ Remove or rename duplicate environment variable entries so each container defines each environment variable name only once.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0295-duplicateenvvar.json)
- `kube-linter` **dangling-horizontalpodautoscaler** — Dangling horizontalpodautoscaler
  - _What:_ Indicates when HorizontalPodAutoscalers target a missing resource.
  - _Fix:_ Confirm that your HorizontalPodAutoscaler's scaleTargetRef correctly matches one of your deployments.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-horizontalpodautoscaler.yaml)
- `kube-linter` **schema-validation** — Schema validation
  - _What:_ Validate Kubernetes resources against their schemas using kubeconform
  - _Fix:_ Fix the resource to conform to the Kubernetes API schema.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/schema-validation.yaml)


## Host files: permissions & ownership

### File permissions / ownership  
_99 rules · tools: kube-bench, kubescape, prowler, trivy_

- `trivy` **KCV-0060** · CRITICAL — Ensure that the admin config file permissions are set to 600 or more restrictive
  - _What:_ [API server] Ensure that the admin config file has permissions of 600 or more restrictive.
  - _Fix:_ Change the admin config file /etc/kubernetes/admin.conf permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_admin_conf_permission.rego)
- `trivy` **KCV-0061** · CRITICAL — Ensure that the admin config file ownership is set to root:root
  - _What:_ [API server] Ensure that the admin config file ownership is set to root:root.
  - _Fix:_ Change the admin config file /etc/kubernetes/admin.conf ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_admin_conf_ownership.rego)
- `trivy` **KCV-0066** · CRITICAL — Ensure that the Kubernetes PKI directory and file file ownership is set to root:root
  - _What:_ [API server] Ensure that the Kubernetes PKI directory and file file ownership is set to root:root.
  - _Fix:_ Change the Kubernetes PKI directory and file file /etc/kubernetes/pki/ ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubernetes_pki_directory_ownership.rego)
- `trivy` **KCV-0067** · CRITICAL — Ensure that the Kubernetes PKI key file permission is set to 600
  - _What:_ [API server] Ensure that the Kubernetes PKI key file permission is set to 600.
  - _Fix:_ Change the Kubernetes PKI key file /etc/kubernetes/pki/*.key permission to 600
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubernetes_pki_key_permission.rego)
- `trivy` **KCV-0070** · CRITICAL — Ensure that the kubelet service file ownership is set to root:root
  - _What:_ [kubelet] Ensure that the kubelet service file ownership is set to root:root.
  - _Fix:_ Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_kublet_service_file_ownership.rego)
- `trivy` **KCV-0075** · CRITICAL — Ensure that the certificate authorities file permissions are set to 600 or more restrictive
  - _What:_ [kubelet] Ensure that the certificate authorities file has permissions of 600 or more restrictive.
  - _Fix:_ Change the certificate authorities file permissions to 600 or more restrictive if exist
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_certificate_authorities_file_permission.rego)
- `trivy` **KCV-0076** · CRITICAL — Ensure that the client certificate authorities file ownership is set to root:root
  - _What:_ [kubelet] Ensure that the certificate authorities file ownership is set to root:root.
  - _Fix:_ Change the certificate authorities file ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_certificate_authorities_file_ownership.rego)
- `kubescape` **C-0102** · HIGH · CIS cis-v1.10.0:1.1.11; cis-v1.12.0:1.1.11 — Ensure that the etcd data directory permissions are set to 700 or more restrictive
  - _What:_ Ensure that the etcd data directory has permissions of `700` or more restrictive.
  - _Fix:_ On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command: ``` ps -ef | grep etcd ``` Run the below command (based on the etcd data directory found above). For example, ``` chmod 700 /var/lib/etcd ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0102-ensurethattheetcddatadirectorypermissionsaresetto700ormorerestrictive.json)
- `kubescape` **C-0103** · HIGH · CIS cis-v1.10.0:1.1.12; cis-v1.12.0:1.1.12 — Ensure that the etcd data directory ownership is set to etcd:etcd
  - _What:_ Ensure that the etcd data directory ownership is set to `etcd:etcd`.
  - _Fix:_ On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command: ``` ps -ef | grep etcd ``` Run the below command (based on the etcd data directory found above). For example, ``` chown etcd:etcd /var/lib/etcd ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0103-ensurethattheetcddatadirectoryownershipissettoetcdetcd.json)
- `kubescape` **C-0104** · HIGH · CIS cis-v1.10.0:1.1.13; cis-v1.12.0:1.1.13 — Ensure that the admin.conf file permissions are set to 600
  - _What:_ Ensure that the `admin.conf` file has permissions of `600`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/admin.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0104-ensurethattheadminconffilepermissionsaresetto600.json)
- `kubescape` **C-0105** · HIGH · CIS cis-v1.10.0:1.1.14; cis-v1.12.0:1.1.14 — Ensure that the admin.conf file ownership is set to root:root
  - _What:_ Ensure that the `admin.conf` file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/admin.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0105-ensurethattheadminconffileownershipissettorootroot.json)
- `kubescape` **C-0110** · HIGH · CIS cis-v1.10.0:1.1.19; cis-v1.12.0:1.1.19 — Ensure that the Kubernetes PKI directory and file ownership is set to root:root
  - _What:_ Ensure that the Kubernetes PKI directory and file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown -R root:root /etc/kubernetes/pki/ ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0110-ensurethatthekubernetespkidirectoryandfileownershipissettorootroot.json)
- `kubescape` **C-0111** · HIGH · CIS cis-v1.10.0:1.1.20; cis-v1.12.0:1.1.20 — Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive
  - _What:_ Ensure that Kubernetes PKI certificate files have permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod -R 600 /etc/kubernetes/pki/*.crt ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0111-ensurethatthekubernetespkicertificatefilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0112** · HIGH · CIS cis-v1.10.0:1.1.21; cis-v1.12.0:1.1.21 — Ensure that the Kubernetes PKI key file permissions are set to 600
  - _What:_ Ensure that Kubernetes PKI key files have permissions of `600`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod -R 600 /etc/kubernetes/pki/*.key ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0112-ensurethatthekubernetespkikeyfilepermissionsaresetto600.json)
- `kubescape` **C-0168** · HIGH · CIS cis-v1.10.0:4.1.7; cis-v1.12.0:4.1.7 — Ensure that the certificate authorities file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the certificate authorities file has permissions of `600` or more restrictive.
  - _Fix:_ Run the following command to modify the file permissions of the `--client-ca-file` ``` chmod 600 <filename> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0168-ensurethatthecertificateauthoritiesfilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0169** · HIGH · CIS cis-v1.10.0:4.1.8; cis-v1.12.0:4.1.8 — Ensure that the client certificate authorities file ownership is set to root:root
  - _What:_ Ensure that the certificate authorities file ownership is set to `root:root`.
  - _Fix:_ Run the following command to modify the ownership of the `--client-ca-file`. ``` chown root:root <filename> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0169-ensurethattheclientcertificateauthoritiesfileownershipissettorootroot.json)
- `kubescape` **C-0170** · HIGH · CIS cis-v1.10.0:4.1.9; cis-v1.12.0:4.1.9 — If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive
  - _What:_ Ensure that if the kubelet refers to a configuration file with the `--config` argument, that file has permissions of 600 or more restrictive.
  - _Fix:_ Run the following command (using the config file location identied in the Audit step) ``` chmod 600 /var/lib/kubelet/config.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0170-ifthekubeletconfigyamlconfigurationfileisbeingusedvalidatepermissionssetto600ormorerestrictive.json)
- `kubescape` **C-0171** · HIGH · CIS cis-aks-t1.2.0:3.1.4; cis-aks-t1.8.0:3.1.4; cis-eks-t1.7.0:3.1.4; cis-eks-t1.8.0:3.1.4; cis-gke-v1.9.0:3.1.4; cis-v1.10.0:4.1.10; cis-v1.12.0:4.1.10 — If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root
  - _What:_ Ensure that if the kubelet refers to a configuration file with the `--config` argument, that file is owned by root:root.
  - _Fix:_ Run the following command (using the config file location identied in the Audit step) ``` chown root:root /etc/kubernetes/kubelet.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0171-ifthekubeletconfigyamlconfigurationfileisbeingusedvalidatefileownershipissettorootroot.json)
- `prowler` **kubelet_conf_file_ownership** · HIGH — Node kubelet.conf file ownership is set to root:root
  - _What:_ **Kubernetes Node kubeconfig** at `/etc/kubernetes/kubelet.conf` is evaluated for file ownership `root:root`. The check focuses on who owns the file that defines the kubelet's API client settings and certificates.
  - _Fix:_ Set `/etc/kubernetes/kubelet.conf` ownership to `root:root` and use restrictive perms (e.g., `600`). Apply **least privilege** on node access, protect kubelet dirs, and enable **file integrity monitoring**. Use **defense in depth**: configuration management to enforce state and periodic audits to …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_conf_file_ownership/kubelet_conf_file_ownership.metadata.json)
- `prowler` **kubelet_conf_file_permissions** · HIGH — Node kubelet.conf file permissions are set to 600 or more restrictive
  - _What:_ **Kubernetes Kubelet kubeconfig** at `/etc/kubernetes/kubelet.conf` must have **owner-only** permissions (`0600` or stricter). The check evaluates the file mode to ensure it is not more permissive than `0600`.
  - _Fix:_ Apply **least privilege** to `/etc/kubernetes/kubelet.conf`: - Set permissions to `0600` or stricter - Restrict ownership to the kubelet user; no group/world access - Limit shell access and monitor file changes - Layer controls with **RBAC** and certificate/key rotation Steps: 1. SSH into the node …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_conf_file_permissions/kubelet_conf_file_permissions.metadata.json)
- `prowler` **kubelet_config_yaml_permissions** · HIGH — Kubelet config.yaml file permissions on the node are set to 600 or more restrictive
  - _What:_ **Kubernetes Kubelet configuration file** (`/var/lib/kubelet/config.yaml`) is evaluated for **restrictive file permissions**. When kubelet uses `--config`, the file is expected to be owner-only readable/writable (`600`) or more restrictive.
  - _Fix:_ Apply **least privilege** to the kubelet config: - Set mode `600` or stricter - Ensure trusted ownership; deny group/world access - Harden the parent directory - Enforce via config management and file integrity monitoring - Limit interactive access to worker nodes Steps: 1. SSH into the affected …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_config_yaml_permissions/kubelet_config_yaml_permissions.metadata.json)
- `prowler` **kubelet_service_file_permissions** · HIGH — Node kubelet service file permissions are set to 600 or more restrictive
  - _What:_ **Kubernetes Kubelet service file** on worker nodes is assessed for restrictive permissions of `600` or tighter. The evaluation reviews the kubelet systemd drop-in configuration to confirm only the owner has read/write access and no broader permissions are granted.
  - _Fix:_ Apply **least privilege**: set the kubelet service file to `600` with root control to block group/other access. Enforce via **configuration management**, restrict administrative shell access to nodes, and monitor with **file integrity** alerts. Use **defense in depth** by maintaining strong …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_service_file_permissions/kubelet_service_file_permissions.metadata.json)
- `trivy` **KCV-0048** · HIGH — Ensure that the API server pod specification file permissions are set to 600 or more restrictive
  - _What:_ [API server] Ensure that the API server pod specification file has permissions of 600 or more restrictive.
  - _Fix:_ Change the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_pod_spec_permission.rego)
- `trivy` **KCV-0049** · HIGH — Ensure that the API server pod specification file ownership is set to root:root
  - _What:_ [API server] Ensure that the API server pod specification file ownership is set to root:root.
  - _Fix:_ Change the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_pod_spec_ownership.rego)
- `trivy` **KCV-0050** · HIGH — Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive
  - _What:_ [controller manager] Ensure that the controller manager pod specification file has permissions of 600 or more restrictive.
  - _Fix:_ Change the controller manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_pod_spec_permission.rego)
- `trivy` **KCV-0051** · HIGH — Ensure that the controller manager pod specification file ownership is set to root:root
  - _What:_ [controller manager] Ensure that the controller manager pod specification file ownership is set to root:root.
  - _Fix:_ Change the controller manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_pod_spec_ownership.rego)
- `trivy` **KCV-0052** · HIGH — Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive
  - _What:_ [scheduler] Ensure that the scheduler pod specification file has permissions of 600 or more restrictive.
  - _Fix:_ Change the scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_pod_spec_permission.rego)
- `trivy` **KCV-0053** · HIGH — Ensure that the scheduler pod specification file ownership is set to root:root
  - _What:_ [scheduler] Ensure that the scheduler pod specification file ownership is set to root:root.
  - _Fix:_ Change the scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_pod_spec_ownership.rego)
- `trivy` **KCV-0054** · HIGH — Ensure that the etcd pod specification file permissions are set to 600 or more restrictive
  - _What:_ [etcd] Ensure that the etcd pod specification file has permissions of 600 or more restrictive.
  - _Fix:_ Change the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_pod_spec_permission.rego)
- `trivy` **KCV-0055** · HIGH — Ensure that the etcd pod specification file ownership is set to root:root
  - _What:_ [etcd] Ensure that the etcd pod specification file ownership is set to root:root.
  - _Fix:_ Change the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_pod_spec_ownership.rego)
- `trivy` **KCV-0056** · HIGH — Ensure that the container network interface file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the container network interface file has permissions of 600 or more restrictive.
  - _Fix:_ Change the container network interface file path/to/cni/files permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/cni_pod_spec_permission.rego)
- `trivy` **KCV-0057** · HIGH — Ensure that the container network interface file ownership is set to root:root
  - _What:_ Ensure that the container network interface file ownership is set to root:root.
  - _Fix:_ Change the container network interface file path/to/cni/files ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/cni_pod_spec_ownership.rego)
- `trivy` **KCV-0062** · HIGH — Ensure that the scheduler config file permissions are set to 600 or more restrictive
  - _What:_ [scheduler] Ensure that the scheduler config file has permissions of 600 or more restrictive.
  - _Fix:_ Change the scheduler config file /etc/kubernetes/scheduler.conf permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_conf_permission.rego)
- `trivy` **KCV-0063** · HIGH — Ensure that the scheduler config file ownership is set to root:root
  - _What:_ [scheduler] Ensure that the scheduler config file ownership is set to root:root.
  - _Fix:_ Change the scheduler config file /etc/kubernetes/scheduler.conf ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/scheduler_conf_ownership.rego)
- `trivy` **KCV-0064** · HIGH — Ensure that the controller-manager config file permissions are set to 600 or more restrictive
  - _What:_ [controller manager] Ensure that the controller-manager config file has permissions of 600 or more restrictive.
  - _Fix:_ Change the controller manager config file /etc/kubernetes/controller-manager.conf permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_controller_manager_conf_permission.rego)
- `trivy` **KCV-0065** · HIGH — Ensure that the controller-manager config file ownership is set to root:root
  - _What:_ [controller manager] Ensure that the controller-manager config file ownership is set to root:root.
  - _Fix:_ Change the controller-manager config file /etc/kubernetes/controller-manager.conf ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_controller_manager_conf_ownership.rego)
- `trivy` **KCV-0068** · HIGH — Ensure that the Kubernetes PKI certificate file permission is set to 600
  - _What:_ [API server] Ensure that the Kubernetes PKI certificate file permission is set to 600.
  - _Fix:_ Change the Kubernetes PKI certificate file /etc/kubernetes/pki/*.crt permission to 600
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubernetes_pki_cert_permission.rego)
- `trivy` **KCV-0069** · HIGH — Ensure that the kubelet service file permissions are set to 600 or more restrictive
  - _What:_ [kubelet] Ensure that the kubelet service file has permissions of 600 or more restrictive.
  - _Fix:_ Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf permissions of 600 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_kublet_service_file_permission.rego)
- `trivy` **KCV-0071** · HIGH — If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive
  - _What:_ [kubelet] If kube-proxy is running, and if it is using a file-based kubeconfig file, ensure that the proxy kubeconfig file has permissions of 600 or more restrictive.
  - _Fix:_ Change the proxy kubeconfig file <path><filename> permissions to 600 or more restrictive if exist
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_proxy_kube_config_file_permission.rego)
- `trivy` **KCV-0072** · HIGH — if proxy kubeconfig file exists ensure ownership is set to root:root
  - _What:_ [kubelet] If kube-proxy is running, ensure that the file ownership of its kubeconfig file is set to root:root.
  - _Fix:_ Change the proxy kubeconfig file <path><filename> ownership to root:root if exist
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_proxy_kube_config_file_ownership.rego)
- `trivy` **KCV-0073** · HIGH — Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive
  - _What:_ [kubelet] Ensure that the kubelet.conf file has permissions of 600 or more restrictive.
  - _Fix:_ Change the kubelet.conf file permissions to 600 or more restrictive if exist
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_config_file_permission.rego)
- `trivy` **KCV-0074** · HIGH — Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root
  - _What:_ [kubelet] Ensure that the kubelet.conf file ownership is set to root:root.
  - _Fix:_ Change the --kubeconfig kubelet.conf file ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_config_file_ownership.rego)
- `trivy` **KCV-0077** · HIGH — If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive
  - _What:_ [kubelet] Ensure that if the kubelet refers to a configuration file with the --config argument, that file has permissions of 600 or more restrictive.
  - _Fix:_ Change the kubelet config yaml permissions to 600 or more restrictive if exist
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_config_yaml_permission.rego)
- `trivy` **KCV-0078** · HIGH — If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root
  - _What:_ [kubelet] Ensure that if the kubelet refers to a configuration file with the --config argument, that file is owned by root:root.
  - _Fix:_ Change the kubelet config.yaml file ownership to root:root
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_config_yaml_ownership.rego)
- `kubescape` **C-0092** · MEDIUM · CIS cis-v1.10.0:1.1.1; cis-v1.12.0:1.1.1 — Ensure that the API server pod specification file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the API server pod specification file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0092-ensurethattheapiserverpodspecificationfilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0093** · MEDIUM · CIS cis-v1.10.0:1.1.2; cis-v1.12.0:1.1.2 — Ensure that the API server pod specification file ownership is set to root:root
  - _What:_ Ensure that the API server pod specification file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0093-ensurethattheapiserverpodspecificationfileownershipissettorootroot.json)
- `kubescape` **C-0094** · MEDIUM · CIS cis-v1.10.0:1.1.3; cis-v1.12.0:1.1.3 — Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0094-ensurethatthecontrollermanagerpodspecificationfilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0095** · MEDIUM · CIS cis-v1.10.0:1.1.4; cis-v1.12.0:1.1.4 — Ensure that the controller manager pod specification file ownership is set to root:root
  - _What:_ Ensure that the controller manager pod specification file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/manifests/kube-controller-manager.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0095-ensurethatthecontrollermanagerpodspecificationfileownershipissettorootroot.json)
- `kubescape` **C-0096** · MEDIUM · CIS cis-v1.10.0:1.1.5; cis-v1.12.0:1.1.5 — Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the scheduler pod specification file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/manifests/kube-scheduler.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0096-ensurethattheschedulerpodspecificationfilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0097** · MEDIUM · CIS cis-v1.10.0:1.1.6; cis-v1.12.0:1.1.6 — Ensure that the scheduler pod specification file ownership is set to root:root
  - _What:_ Ensure that the scheduler pod specification file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/manifests/kube-scheduler.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0097-ensurethattheschedulerpodspecificationfileownershipissettorootroot.json)
- `kubescape` **C-0098** · MEDIUM · CIS cis-v1.10.0:1.1.7; cis-v1.12.0:1.1.7 — Ensure that the etcd pod specification file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the `/etc/kubernetes/manifests/etcd.yaml` file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/manifests/etcd.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0098-ensurethattheetcdpodspecificationfilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0099** · MEDIUM · CIS cis-v1.10.0:1.1.8; cis-v1.12.0:1.1.8 — Ensure that the etcd pod specification file ownership is set to root:root
  - _What:_ Ensure that the `/etc/kubernetes/manifests/etcd.yaml` file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/manifests/etcd.yaml ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0099-ensurethattheetcdpodspecificationfileownershipissettorootroot.json)
- `kubescape` **C-0100** · MEDIUM · CIS cis-v1.10.0:1.1.9; cis-v1.12.0:1.1.9 — Ensure that the Container Network Interface file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the Container Network Interface files have permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 <path/to/cni/files> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0100-ensurethatthecontainernetworkinterfacefilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0101** · MEDIUM · CIS cis-v1.10.0:1.1.10; cis-v1.12.0:1.1.10 — Ensure that the Container Network Interface file ownership is set to root:root
  - _What:_ Ensure that the Container Network Interface files have ownership set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root <path/to/cni/files> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0101-ensurethatthecontainernetworkinterfacefileownershipissettorootroot.json)
- `kubescape` **C-0106** · MEDIUM · CIS cis-v1.10.0:1.1.15; cis-v1.12.0:1.1.15 — Ensure that the scheduler.conf file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the `scheduler.conf` file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/scheduler.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0106-ensurethattheschedulerconffilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0107** · MEDIUM · CIS cis-v1.10.0:1.1.16; cis-v1.12.0:1.1.16 — Ensure that the scheduler.conf file ownership is set to root:root
  - _What:_ Ensure that the `scheduler.conf` file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/scheduler.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0107-ensurethattheschedulerconffileownershipissettorootroot.json)
- `kubescape` **C-0108** · MEDIUM · CIS cis-v1.10.0:1.1.17; cis-v1.12.0:1.1.17 — Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the `controller-manager.conf` file has permissions of 600 or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chmod 600 /etc/kubernetes/controller-manager.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0108-ensurethatthecontrollermanagerconffilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0109** · MEDIUM · CIS cis-v1.10.0:1.1.18; cis-v1.12.0:1.1.18 — Ensure that the controller-manager.conf file ownership is set to root:root
  - _What:_ Ensure that the `controller-manager.conf` file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the Control Plane node. For example, ``` chown root:root /etc/kubernetes/controller-manager.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0109-ensurethatthecontrollermanagerconffileownershipissettorootroot.json)
- `kubescape` **C-0162** · MEDIUM · CIS cis-v1.10.0:4.1.1; cis-v1.12.0:4.1.1 — Ensure that the kubelet service file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the `kubelet` service file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chmod 600 /etc/systemd/system/kubelet.service.d/kubeadm.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0162-ensurethatthekubeletservicefilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0163** · MEDIUM · CIS cis-v1.10.0:4.1.2; cis-v1.12.0:4.1.2 — Ensure that the kubelet service file ownership is set to root:root
  - _What:_ Ensure that the `kubelet` service file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chown root:root /etc/systemd/system/kubelet.service.d/kubeadm.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0163-ensurethatthekubeletservicefileownershipissettorootroot.json)
- `kubescape` **C-0164** · MEDIUM · CIS cis-gke-v1.9.0:3.1.1; cis-v1.10.0:4.1.3; cis-v1.12.0:4.1.3 — If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive
  - _What:_ If `kube-proxy` is running, and if it is using a file-based kubeconfig file, ensure that the proxy kubeconfig file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chmod 600 <proxy kubeconfig file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0164-ifproxykubeconfigfileexistsensurepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0165** · MEDIUM · CIS cis-gke-v1.9.0:3.1.2; cis-v1.10.0:4.1.4; cis-v1.12.0:4.1.4 — If proxy kubeconfig file exists ensure ownership is set to root:root
  - _What:_ If `kube-proxy` is running, ensure that the file ownership of its kubeconfig file is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chown root:root <proxy kubeconfig file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0165-ifproxykubeconfigfileexistsensureownershipissettorootroot.json)
- `kubescape` **C-0166** · MEDIUM · CIS cis-v1.10.0:4.1.5; cis-v1.12.0:4.1.5 — Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive
  - _What:_ Ensure that the `kubelet.conf` file has permissions of `600` or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chmod 600 /etc/kubernetes/kubelet.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0166-ensurethatthekubeconfigkubeletconffilepermissionsaresetto600ormorerestrictive.json)
- `kubescape` **C-0167** · MEDIUM · CIS cis-aks-t1.2.0:3.1.2; cis-aks-t1.8.0:3.1.2; cis-eks-t1.7.0:3.1.2; cis-eks-t1.8.0:3.1.2; cis-v1.10.0:4.1.6; cis-v1.12.0:4.1.6 — Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root
  - _What:_ Ensure that the `kubelet.conf` file ownership is set to `root:root`.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chown root:root /etc/kubernetes/kubelet.conf ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0167-ensurethatthekubeconfigkubeletconffileownershipissettorootroot.json)
- `kubescape` **C-0235** · MEDIUM · CIS cis-aks-t1.2.0:3.1.3; cis-aks-t1.8.0:3.1.3; cis-eks-t1.7.0:3.1.3; cis-eks-t1.8.0:3.1.3; cis-gke-v1.9.0:3.1.3 — Ensure that the kubelet configuration file has permissions set to 644 or more restrictive
  - _What:_ Ensure that if the kubelet refers to a configuration file with the `--config` argument, that file has permissions of 644 or more restrictive.
  - _Fix:_ Run the following command (using the config file location identified in the Audit step) ``` chmod 644 /etc/kubernetes/kubelet/kubelet-config.json ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0235-ensurethatthekubeletconfigurationfilehaspermissionssetto644ormorerestrictive.json)
- `kubescape` **C-0238** · MEDIUM · CIS cis-aks-t1.2.0:3.1.1; cis-aks-t1.8.0:3.1.1; cis-eks-t1.7.0:3.1.1; cis-eks-t1.8.0:3.1.1 — Ensure that the kubeconfig file permissions are set to 644 or more restrictive
  - _What:_ If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig file has permissions of 644 or more restrictive.
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, ``` chmod 644 <kubeconfig file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0238-ensurethatthekubeconfigfilepermissionsaresetto644ormorerestrictive.json)
- `trivy` **KCV-0058** · LOW — Ensure that the etcd data directory permissions are set to 700 or more restrictive
  - _What:_ [etcd] Ensure that the etcd data directory has permissions of 700 or more restrictive.
  - _Fix:_ Change the etcd data directory /var/lib/etcd permissions of 700 or more restrictive
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_data_directory_permission.rego)
- `trivy` **KCV-0059** · LOW — Ensure that the etcd data directory ownership is set to etcd:etcd
  - _What:_ [etcd] Ensure that the etcd data directory ownership is set to etcd:etcd.
  - _Fix:_ Change the etcd data directory /var/lib/etcd ownership to etcd:etcd
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_data_directory_ownership.rego)
- `kube-bench` **1.1.1** · CIS cis-1.11:1.1.1 — Ensure that the API server pod specification file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the API server pod specification file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $apiserverconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.10** · manual · CIS cis-1.11:1.1.10 — Ensure that the Container Network Interface file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the Container Network Interface file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root <path/to/cni/files>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.11** · CIS cis-1.11:1.1.11 — Ensure that the etcd data directory permissions are set to 700 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the etcd data directory permissions are set to 700 or more restrictive
  - _Fix:_ On the etcd server node, get the etcd data directory, passed as an argument --data-dir, from the command 'ps -ef | grep etcd'. Run the below command (based on the etcd data directory found above). For example, chmod 700 /var/lib/etcd
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.12** · CIS cis-1.11:1.1.12 — Ensure that the etcd data directory ownership is set to etcd:etcd
  - _What:_ [Control Plane Node Configuration Files] Ensure that the etcd data directory ownership is set to etcd:etcd
  - _Fix:_ On the etcd server node, get the etcd data directory, passed as an argument --data-dir, from the command 'ps -ef | grep etcd'. Run the below command (based on the etcd data directory found above). For example, chown etcd:etcd /var/lib/etcd
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.13** · CIS cis-1.11:1.1.13 — Ensure that the default administrative credential file permissions are set to 600
  - _What:_ [Control Plane Node Configuration Files] Ensure that the default administrative credential file permissions are set to 600
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 /etc/kubernetes/admin.conf On Kubernetes 1.29+ the super-admin.conf file should also be modified, if present. For example, chmod 600 /etc/kubernetes/super-admin.conf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.14** · CIS cis-1.11:1.1.14 — Ensure that the default administrative credential file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the default administrative credential file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root /etc/kubernetes/admin.conf On Kubernetes 1.29+ the super-admin.conf file should also be modified, if present. For example, chown root:root /etc/kubernetes/super-admin.conf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.15** · CIS cis-1.11:1.1.15 — Ensure that the scheduler.conf file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the scheduler.conf file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $schedulerkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.16** · CIS cis-1.11:1.1.16 — Ensure that the scheduler.conf file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the scheduler.conf file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $schedulerkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.17** · CIS cis-1.11:1.1.17 — Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $controllermanagerkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.18** · CIS cis-1.11:1.1.18 — Ensure that the controller-manager.conf file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the controller-manager.conf file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $controllermanagerkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.19** · CIS cis-1.11:1.1.19 — Ensure that the Kubernetes PKI directory and file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the Kubernetes PKI directory and file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown -R root:root /etc/kubernetes/pki/
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.2** · CIS cis-1.11:1.1.2 — Ensure that the API server pod specification file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the API server pod specification file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $apiserverconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.20** · manual · CIS cis-1.11:1.1.20 — Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod -R 644 /etc/kubernetes/pki/*.crt
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.21** · manual · CIS cis-1.11:1.1.21 — Ensure that the Kubernetes PKI key file permissions are set to 600
  - _What:_ [Control Plane Node Configuration Files] Ensure that the Kubernetes PKI key file permissions are set to 600
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod -R 600 /etc/kubernetes/pki/*.key
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.3** · CIS cis-1.11:1.1.3 — Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $controllermanagerconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.4** · CIS cis-1.11:1.1.4 — Ensure that the controller manager pod specification file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the controller manager pod specification file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $controllermanagerconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.5** · CIS cis-1.11:1.1.5 — Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $schedulerconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.6** · CIS cis-1.11:1.1.6 — Ensure that the scheduler pod specification file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the scheduler pod specification file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $schedulerconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.7** · CIS cis-1.11:1.1.7 — Ensure that the etcd pod specification file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the etcd pod specification file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 $etcdconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.8** · CIS cis-1.11:1.1.8 — Ensure that the etcd pod specification file ownership is set to root:root
  - _What:_ [Control Plane Node Configuration Files] Ensure that the etcd pod specification file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root $etcdconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.1.9** · manual · CIS cis-1.11:1.1.9 — Ensure that the Container Network Interface file permissions are set to 600 or more restrictive
  - _What:_ [Control Plane Node Configuration Files] Ensure that the Container Network Interface file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 <path/to/cni/files>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **4.1.1** · CIS cis-1.11:4.1.1 — Ensure that the kubelet service file permissions are set to 600 or more restrictive
  - _What:_ [Worker Node Configuration Files] Ensure that the kubelet service file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chmod 600 $kubeletsvc
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.10** · CIS cis-1.11:4.1.10 — If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root
  - _What:_ [Worker Node Configuration Files] If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root
  - _Fix:_ Run the following command (using the config file location identified in the Audit step) chown root:root $kubeletconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.2** · CIS cis-1.11:4.1.2 — Ensure that the kubelet service file ownership is set to root:root
  - _What:_ [Worker Node Configuration Files] Ensure that the kubelet service file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root $kubeletsvc
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.3** · manual · CIS cis-1.11:4.1.3 — If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive
  - _What:_ [Worker Node Configuration Files] If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chmod 600 $proxykubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.4** · manual · CIS cis-1.11:4.1.4 — If proxy kubeconfig file exists ensure ownership is set to root:root
  - _What:_ [Worker Node Configuration Files] If proxy kubeconfig file exists ensure ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root $proxykubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.5** · CIS cis-1.11:4.1.5 — Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive
  - _What:_ [Worker Node Configuration Files] Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chmod 600 $kubeletkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.6** · CIS cis-1.11:4.1.6 — Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root
  - _What:_ [Worker Node Configuration Files] Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root
  - _Fix:_ Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root $kubeletkubeconfig
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.7** · manual · CIS cis-1.11:4.1.7 — Ensure that the certificate authorities file permissions are set to 644 or more restrictive
  - _What:_ [Worker Node Configuration Files] Ensure that the certificate authorities file permissions are set to 644 or more restrictive
  - _Fix:_ Run the following command to modify the file permissions of the --client-ca-file chmod 644 <filename>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.8** · manual · CIS cis-1.11:4.1.8 — Ensure that the client certificate authorities file ownership is set to root:root
  - _What:_ [Worker Node Configuration Files] Ensure that the client certificate authorities file ownership is set to root:root
  - _Fix:_ Run the following command to modify the ownership of the --client-ca-file. chown root:root <filename>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.1.9** · CIS cis-1.11:4.1.9 — If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive
  - _What:_ [Worker Node Configuration Files] If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive
  - _Fix:_ Run the following command (using the config file location identified in the Audit step) chmod 600 $kubeletconf
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)


## Known vulnerabilities & legacy components

### Known CVEs / outdated versions  
_17 rules · tools: checkov, gatekeeper, kubescape, kyverno_

- `kubescape` **C-0090** · CRITICAL — CVE-2022-39328-grafana-auth-bypass
  - _What:_ CVE-2022-39328 is a critical vulnerability in Grafana, it might enable attacker to access unauthorized endpoints under heavy load.
  - _Fix:_ Update your Grafana to 9.2.4 or above
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0090-cve202239328grafanaauthbypass.json)
- `kubescape` **C-0059** · HIGH — CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability
  - _What:_ Security issue in ingress-nginx where a user that can create or update ingress objects can use the custom snippets feature to obtain all secrets in the cluster (see more at https://github.com/kubernetes/ingress-nginx/issues/7837)
  - _Fix:_ To mitigate this vulnerability: 1. Upgrade to a version that allows mitigation (>= v0.49.1 or >= v1.0.1), 2. Set allow-snippet-annotations to false in your ingress-nginx ConfigMap based on how you deploy ingress-nginx
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0059-cve202125742nginxingresssnippetannotationvulnerability.json)
- `kubescape` **C-0087** · HIGH — CVE-2022-23648-containerd-fs-escape
  - _What:_ CVE-2022-23648 is a vulnerability of containerd enabling attacker to gain access to read-only copies of arbitrary files from the host using specially-crafted manifests
  - _Fix:_ Patch containerd to 1.6.1, 1.5.10, 1.4.12 or above
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0087-cve202223648containerdfsescape.json)
- `kubescape` **C-0091** · HIGH — CVE-2022-47633-kyverno-signature-bypass
  - _What:_ CVE-2022-47633 is a high severity vulnerability in Kyverno, it enables attackers to bypass the image signature validation of policies using a malicious image repository or MITM proxy
  - _Fix:_ Update your Grafana to 9.2.4 or above
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0091-cve202247633kyvernosignaturebypass.json)
- `kyverno` **check-kernel** · HIGH — Check Node for CVE-2022-0185
  - _What:_ Linux CVE-2022-0185 can allow a container escape in Kubernetes if left unpatched. The affected Linux kernel versions, at this time, are 5.10.84-1 and 5.15.5-2. For more information, refer to https://security-tracker.debian.org/tracker/CVE-2022-0185. This policy runs in background mode and flags an entry in the ValidatingPolicyReport if any Node is reporting one of the affected kernel versions.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-node-for-cve-2022-0185/check-node-for-cve-2022-0185.yaml)
- `kyverno` **prevent-cr8escape** · HIGH — Prevent cr8escape (CVE-2022-0811)
  - _What:_ A vulnerability "cr8escape" (CVE-2022-0811) in CRI-O the container runtime engine underpinning Kubernetes allows attackers to escape from a Kubernetes container and gain root access to the host. The recommended remediation is to disallow sysctl settings with + or = in their value.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/prevent-cr8escape/prevent-cr8escape.yaml)
- `kubescape` **C-0058** · MEDIUM — CVE-2021-25741 - Using symlink for arbitrary host file system access.
  - _What:_ A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster. If you …
  - _Fix:_ To mitigate this vulnerability without upgrading kubelet, you can disable the VolumeSubpath feature gate on kubelet and kube-apiserver, or remove any existing Pods using subPath or subPathExpr feature.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0058-cve202125741usingsymlinkforarbitraryhostfilesystemaccess.json)
- `kubescape` **C-0079** · MEDIUM — CVE-2022-0185-linux-kernel-container-escape
  - _What:_ CVE-2022-0185 is a kernel vulnerability enabling privilege escalation and it can lead attackers to escape containers and take control over nodes. This control alerts on vulnerable kernel versions of Kubernetes nodes
  - _Fix:_ Patch Linux kernel version to 5.16.2 or above
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0079-cve20220185linuxkernelcontainerescape.json)
- `kubescape` **C-0081** · MEDIUM — CVE-2022-24348-argocddirtraversal
  - _What:_ CVE-2022-24348 is a major software supply chain 0-day vulnerability in the popular open source CD platform Argo CD which can lead to privilege escalation and information disclosure.
  - _Fix:_ Update your ArgoCD deployment to fixed versions (v2.1.9,v2.2.4 or v2.3.0)
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0081-cve202224348argocddirtraversal.json)
- `kubescape` **C-0089** · LOW — CVE-2022-3172-aggregated-API-server-redirect
  - _What:_ The API server allows an aggregated API to redirect client traffic to any URL. This could lead to the client performing unexpected actions as well as forwarding the client's API server credentials to third parties
  - _Fix:_ Upgrade the Kubernetes version to one of the following versions (or higher patchs): `v1.25.1`, `v1.24.5`, `v1.23.11`, `v1.22.14`
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0089-cve20223172aggregatedapiserverredirect.json)
- `kubescape` **C-0273** · LOW — Outdated Kubernetes version
  - _What:_ Identifies Kubernetes clusters running on outdated versions. Using old versions can expose clusters to known vulnerabilities, compatibility issues, and miss out on improved features and security patches. Keeping Kubernetes up-to-date is crucial for maintaining security and operational efficiency.
  - _Fix:_ Regularly update Kubernetes clusters to the latest stable version to mitigate known vulnerabilities and enhance functionality. Plan and execute upgrades considering workload compatibility, testing in a staging environment before applying changes to production. Follow Kubernetes' best practices for …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0273-outdatedk8sversion.json)
- `checkov` **CKV2_K8S_4** — ServiceAccounts and nodes that can modify services/status may set the `status.loadBalancer.ingress.ip` field to exploit the unfixed CVE-2020-8554 and launch MiTM attacks against the cluster.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/ModifyServicesStatus.yaml)
- `checkov` **CKV_K8S_152** — Prevent NGINX Ingress annotation snippets which contain LUA code execution. See CVE-2021-25742
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742Lua.py)
- `checkov` **CKV_K8S_153** — Prevent All NGINX Ingress annotation snippets. See CVE-2021-25742
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742AllSnippets.py)
- `checkov` **CKV_K8S_154** — Prevent NGINX Ingress annotation snippets which contain alias statements See CVE-2021-25742
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742Alias.py)
- `gatekeeper` **k8sblockendpointeditdefaultrole** — Block Endpoint Edit Default Role
  - _What:_ Many Kubernetes installations by default have a system:aggregate-to-edit ClusterRole which does not properly restrict access to editing Endpoints. This ConstraintTemplate forbids the system:aggregate-to-edit ClusterRole from granting permission to create/patch/update Endpoints. ClusterRole/system:aggregate-to-edit should not allow Endpoint edit permissions due to CVE-2021-25740, Endpoint & …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/block-endpoint-edit-default-role/template.yaml)
- `kyverno` **restrict-node-label-creation** — Restrict node label creation
  - _What:_ Node labels are critical pieces of metadata upon which many other applications and logic may depend and should not be altered or removed by regular users. Many cloud providers also use Node labels to signal specific functions to applications. This policy prevents setting of a new label called `foo` on cluster Nodes. Use of this policy requires removal of the Node resource filter in the Kyverno …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-node-label-creation/restrict-node-label-creation.yaml)

### Legacy / risky components (Tiller, dashboard, SSH)  
_7 rules · tools: checkov, kubescape, kyverno, trivy_

- `trivy` **KSV-0102** · CRITICAL — Tiller Is Deployed
  - _What:_ Check if Helm Tiller component is deployed.
  - _Fix:_ Migrate to Helm v3 which no longer has Tiller component
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/tiller_is_deployed.rego)
- `kyverno` **disallow-helm-tiller** · MEDIUM — Disallow Helm Tiller in VPOL
  - _What:_ Tiller, found in Helm v2, has known security challenges. It requires administrative privileges and acts as a shared resource accessible to any authenticated user. Tiller can lead to privilege escalation as restricted users can impact other users. It is recommend to use Helm v3+ which does not contain Tiller for these reasons. This policy validates that there is not an image containing the name …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/disallow-helm-tiller/disallow-helm-tiller.yaml)
- `kubescape` **C-0014** · LOW · CIS cis-gke-v1.9.0:5.10.1 — Access Kubernetes dashboard
  - _What:_ Attackers who gain access to the dashboard service account or have its RBAC permissions can use its network access to retrieve information about resources in the cluster or change them. This control checks if a subject that is not dashboard service account is bound to dashboard role/clusterrole, or - if anyone that is not the dashboard pod is associated with dashboard service account.
  - _Fix:_ Make sure that the “Kubernetes Dashboard” service account is only bound to the Kubernetes dashboard following the least privilege principle.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0014-accesskubernetesdashboard.json)
- `checkov` **CKV_K8S_33** — Ensure the Kubernetes dashboard is not deployed
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubernetesDashboard.py)
- `checkov` **CKV_K8S_34** — Ensure that Tiller (Helm v2) is not deployed
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/Tiller.py)
- `checkov` **CKV_K8S_44** — Ensure that the Tiller Service (Helm v2) is deleted
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/TillerService.py)
- `checkov` **CKV_K8S_45** — Ensure the Tiller Deployment (Helm V2) is not accessible from within the cluster
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/TillerDeploymentListener.py)

### NodePort / LoadBalancer / external exposure  
_1 rules · tools: trivy_

- `trivy` **KSV-0108** · HIGH — Service with External IP
  - _What:_ Services with external IP addresses allows direct access from the internet and might expose risk for CVE-2020-8554
  - _Fix:_ Do not set spec.externalIPs
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/service_with_externalip.rego)

### TLS / certificates / ciphers  
_1 rules · tools: kubescape_

- `kubescape` **C-0077** · LOW — K8s common labels usage
  - _What:_ Kubernetes common labels help manage and monitor Kubernetes cluster using different tools such as kubectl, dashboard and others in an interoperable way. Refer to https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/ for more information. This control helps you find objects that don't have any of these labels defined.
  - _Fix:_ Define applicable labels or use the exception mechanism to prevent further notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0077-k8scommonlabelsusage.json)


## Managed Kubernetes (EKS/AKS/GKE) & cloud

### Allowed / trusted registries  
_7 rules · tools: kubescape, kyverno_

- `kubescape` **C-0001** · HIGH — Forbidden Container Registries
  - _What:_ In cases where the Kubernetes cluster is provided by a CSP (e.g., AKS in Azure, GKE in GCP, or EKS in AWS), compromised cloud credential can lead to the cluster takeover. Attackers may abuse cloud account credentials or IAM mechanism to the cluster’s management layer.
  - _Fix:_ Limit the registries from which you pull container images from
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0001-forbiddencontainerregistries.json)
- `kyverno` **restrict-deprecated-registry** · HIGH — Restrict Deprecated Registry
  - _What:_ Legacy k8s.gcr.io container image registry will be frozen in early April 2023 k8s.gcr.io image registry will be frozen from the 3rd of April 2023. Images for Kubernetes 1.27 will not be available in the k8s.gcr.io image registry. Please read our announcement for more details. https://kubernetes.io/blog/2023/02/06/k8s-gcr-io-freeze-announcement/
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-deprecated-registry/restrict-deprecated-registry.yaml)
- `kubescape` **C-0250** · MEDIUM · CIS cis-aks-t1.2.0:5.1.2; cis-aks-t1.8.0:5.1.2 — Minimize cluster access to read-only for Azure Container Registry (ACR)
  - _What:_ Configure the Cluster Service Account with Storage Object Viewer Role to only allow read-only access to Azure Container Registry (ACR)
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0250-minimizeclusteraccesstoreadonlyforazurecontainerregistryacr.json)
- `kubescape` **C-0251** · MEDIUM · CIS cis-aks-t1.2.0:5.1.3; cis-aks-t1.8.0:5.1.3 — Minimize user access to Azure Container Registry (ACR)
  - _What:_ Restrict user access to Azure Container Registry (ACR), limiting interaction with build images to only authorized personnel and service accounts.
  - _Fix:_ Azure Container Registry If you use Azure Container Registry (ACR) as your container image store, you need to grant permissions to the service principal for your AKS cluster to read and pull images. Currently, the recommended configuration is to use the az aks create or az aks update command to …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0251-minimizeuseraccesstoazurecontainerregistryacr.json)
- `kubescape` **C-0308** · MEDIUM · CIS cis-gke-v1.9.0:5.1.2 — Minimize user access to GCP Artifact Registry
  - _What:_ Restrict user access to GCP Artifact Registry, limiting interaction with build images to only authorized personnel and service accounts.
  - _Fix:_ Review the IAM bindings for GCP Artifact Registry repositories and ensure that only authorized accounts have roles such as roles/artifactregistry.writer or roles/artifactregistry.admin.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0308-minimizeuseraccesstoartifactregistrygcp.json)
- `kyverno` **restrict-image-registries** · MEDIUM — Restrict Image Registries in VPOL
  - _What:_ Images from unknown, public registries can be of dubious quality and may not be scanned and secured, representing a high degree of risk. Requiring use of known, approved registries helps reduce threat exposure by ensuring image pulls only come from them. This policy validates that container images only originate from the registry `eu.foo.io` or `bar.io`. Use of this policy requires customization …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/restrict-image-registries/restrict-image-registries.yaml)
- `kubescape` **C-0233** · LOW · CIS cis-gke-v1.9.0:5.10.3 — Consider Fargate for running untrusted workloads
  - _What:_ It is Best Practice to restrict or fence untrusted workloads when running in a multi-tenant environment.
  - _Fix:_ **Create a Fargate profile for your cluster** Before you can schedule pods running on Fargate in your cluster, you must define a Fargate profile that specifies which pods should use Fargate when they are launched. For more information, see AWS Fargate profile. **Note** If you created your cluster …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0233-considerfargateforrunninguntrustedworkloads.json)

### Cloud metadata / IAM  
_5 rules · tools: kubescape, trivy_

- `trivy` **KSV-0115** · CRITICAL — Manage EKS IAM Auth ConfigMap
  - _What:_ Ability to add AWS IAM to RBAC bindings via special EKS configmap.
  - _Fix:_ Remove write permission verbs for resource 'configmaps' named 'aws-auth'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_eks_iam_auth_configmap.rego)
- `kubescape` **C-0052** · HIGH — Instance Metadata API
  - _What:_ Attackers who gain access to a container, may query the metadata API service for getting information about the underlying node. This control checks if there is access from the nodes to cloud providers instance metadata services.
  - _Fix:_ Disable metadata services for pods in cloud provider settings.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0052-instancemetadataapi.json)
- `kubescape` **C-0225** · HIGH · CIS cis-eks-t1.7.0:5.2.1; cis-eks-t1.8.0:5.2.1; cis-gke-v1.9.0:5.2.2 — Prefer using dedicated EKS Service Accounts
  - _What:_ Kubernetes workloads should not use cluster node service accounts to authenticate to Amazon EKS APIs. Each Kubernetes workload that needs to authenticate to other AWS services using AWS IAM should be provisioned with a dedicated Service account.
  - _Fix:_ With IAM roles for service accounts on Amazon EKS clusters, you can associate an IAM role with a Kubernetes service account. This service account can then provide AWS permissions to the containers in any pod that uses that service account. With this feature, you no longer need to provide extended …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0225-preferusingdedicatedeksserviceaccounts.json)
- `kubescape` **C-0232** · HIGH · CIS cis-eks-t1.7.0:5.5.1; cis-eks-t1.8.0:5.5.1; cis-gke-v1.9.0:5.8.2 — Manage Kubernetes RBAC users with AWS IAM Authenticator for Kubernetes or Upgrade to AWS CLI v1.16.156
  - _What:_ Amazon EKS uses IAM to provide authentication to your Kubernetes cluster through the AWS IAM Authenticator for Kubernetes. You can configure the stock kubectl client to work with Amazon EKS by installing the AWS IAM Authenticator for Kubernetes and modifying your kubectl configuration file to use it for authentication.
  - _Fix:_ Refer to the '[Managing users or IAM roles for your cluster](https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html)' in Amazon EKS documentation. Note: If using AWS CLI version 1.16.156 or later there is no need to install the AWS IAM Authenticator anymore. The relevant AWS CLI …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0232-managekubernetesrbacuserswithawsiamauthenticatorforkubernetesorupgradetoawscliv116156.json)
- `kubescape` **C-0239** · HIGH · CIS cis-aks-t1.2.0:5.2.1; cis-aks-t1.8.0:5.2.1 — Prefer using dedicated AKS Service Accounts
  - _What:_ Kubernetes workloads should not use cluster node service accounts to authenticate to Azure AKS APIs. Each Kubernetes workload that needs to authenticate to other Azure Web Services using IAM should be provisioned with a dedicated Service account.
  - _Fix:_ Azure Active Directory integration The security of AKS clusters can be enhanced with the integration of Azure Active Directory (AD). Built on decades of enterprise identity management, Azure AD is a multi-tenant, cloud-based directory, and identity management service that combines core directory …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0239-preferusingdedicatedaksserviceaccounts.json)

### Encryption at rest / KMS  
_1 rules · tools: kubescape_

- `kubescape` **C-0244** · MEDIUM · CIS cis-aks-t1.2.0:5.3.1; cis-aks-t1.8.0:5.3.1 — Ensure Kubernetes Secrets are encrypted
  - _What:_ Encryption at Rest is a common security requirement. In Azure, organizations can encrypt data at rest without the risk or cost of a custom key management solution. Organizations have the option of letting Azure completely manage Encryption at Rest. Additionally, organizations have various options to closely manage encryption or encryption keys.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0244-ensurekubernetessecretsareencrypted.json)

### File permissions / ownership  
_1 rules · tools: kubescape_

- `kubescape` **C-0285** · MEDIUM · CIS cis-eks-t1.7.0:4.1.7; cis-eks-t1.8.0:4.1.7 — Cluster Access Manager API to streamline and enhance the management of access controls within EKS clusters
  - _What:_ Amazon EKS has introduced the Cluster Access Manager API to streamline and enhance the management of access controls within EKS clusters. This new approach is now the recommended method over the traditional `aws-auth` ConfigMap for managing Role-Based Access Control (RBAC) and Service Accounts. Key Advantages of Using the Cluster Access Manager API: 1. **Simplified Access Management:** The …
  - _Fix:_ Log in to the AWS Management Console. Navigate to Amazon EKS and select your EKS cluster. Go to the Access tab and click on "Manage Access" in the "Access Configuration section". Under Cluster Authentication Mode for Cluster Access settings. * Click `EKS API` to change `cluster will source …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0285-clusteraccessmanagerapitostreamlineandenhancethemanagementofaccesscontrolswithineksclusters.json)

### Host network  
_1 rules · tools: kubescape_

- `kubescape` **C-0041** · HIGH · CIS cis-v1.10.0:5.2.5; cis-v1.12.0:5.2.5 — HostNetwork access
  - _What:_ Potential attackers may gain access to a pod and inherit access to the entire host network. For example, in AWS case, they will have access to the entire VPC. This control identifies all the pods with host network access enabled.
  - _Fix:_ Only connect pods to host network when it is necessary. If not, set the hostNetwork field of the pod spec to false, or completely remove it (false is the default). Whitelist only those pods that must have access to host network by design.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0041-hostnetworkaccess.json)

### Image signing & verification  
_2 rules · tools: kubescape, kyverno_

- `kyverno` **verify-image-ivpol** · MEDIUM — Verify Image
  - _What:_ Using the Cosign project, OCI images may be signed to ensure supply chain security is maintained. Those signatures can be verified before pulling into a cluster. This policy checks the signature of an image repo called ghcr.io/kyverno/test-verify-image to ensure it has been signed by verifying its signature against the provided public key. This policy serves as an illustration for how to …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other/verify-image-ivpol/verify-image-ivpol.yaml)
- `kubescape` **C-0226** · LOW · CIS cis-gke-v1.9.0:5.5.1 — Prefer using a container-optimized OS when possible
  - _What:_ A container-optimized OS is an operating system image that is designed for secure managed hosting of containers on compute instances. Use cases for container-optimized OSes might include: * Docker container or Kubernetes support with minimal setup. * A small-secure container footprint. * An OS that is tested, hardened and verified for running Kubernetes nodes in your compute instances.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0226-preferusingacontaineroptimizedoswhenpossible.json)

### Linux capabilities  
_1 rules · tools: kubescape_

- `kubescape` **C-0243** · MEDIUM · CIS cis-aks-t1.2.0:5.1.1; cis-aks-t1.8.0:5.1.1 — Ensure Image Vulnerability Scanning using Azure Defender image scanning or a third party provider
  - _What:_ Scan images being deployed to Azure (AKS) for vulnerabilities. Vulnerability scanning for images stored in Azure Container Registry is generally available in Azure Security Center. This capability is powered by Qualys, a leading provider of information security. When you push an image to Container Registry, Security Center automatically scans it, then checks for known vulnerabilities in packages …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0243-ensureimagevulnerabilityscanningusingazuredefenderimagescanningorathirdpartyprovider.json)

### Network policies  
_2 rules · tools: kubescape_

- `kubescape` **C-0230** · MEDIUM · CIS cis-eks-t1.7.0:5.4.4; cis-eks-t1.8.0:5.4.4 — Ensure Network Policy is Enabled and set as appropriate
  - _What:_ Amazon EKS provides two ways to implement network policy. You choose a network policy option when you create an EKS cluster. The policy option can't be changed after the cluster is created: Calico Network Policies, an open-source network and network security solution founded by Tigera. Both implementations use Linux IPTables to enforce the specified policies. Policies are translated into sets of …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0230-ensurenetworkpolicyisenabledandsetasappropriate.json)
- `kubescape` **C-0240** · MEDIUM · CIS cis-aks-t1.2.0:5.4.4; cis-aks-t1.8.0:5.4.4 — Ensure Network Policy is Enabled and set as appropriate
  - _What:_ When you run modern, microservices-based applications in Kubernetes, you often want to control which components can communicate with each other. The principle of least privilege should be applied to how traffic can flow between pods in an Azure Kubernetes Service (AKS) cluster. Let's say you likely want to block traffic directly to back-end applications. The Network Policy feature in Kubernetes …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0240-ensurenetworkpolicyisenabledandsetasappropriate.json)

### Pod Security Standards / PSA / PSP  
_1 rules · tools: kubescape_

- `kubescape` **C-0242** · MEDIUM · CIS cis-aks-t1.2.0:5.6.2; cis-aks-t1.8.0:5.6.2 — Hostile multi-tenant workloads
  - _What:_ Currently, Kubernetes environments aren't safe for hostile multi-tenant usage. Extra security features, like Pod Security Policies or Kubernetes RBAC for nodes, efficiently block exploits. For true security when running hostile multi-tenant workloads, only trust a hypervisor. The security domain for Kubernetes becomes the entire cluster, not an individual node. For these types of hostile …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0242-hostilemultitenantworkloads.json)

### Privilege escalation  
_1 rules · tools: kyverno_

- `kyverno` **disallow-container-sock-mounts** · MEDIUM — Disallow CRI socket mounts in VPOL
  - _What:_ Container daemon socket bind mounts allows access to the container engine on the node. This access can be used for privilege escalation and to manage containers outside of Kubernetes, and hence should not be allowed. This policy validates that the sockets used for CRI engines Docker, Containerd, and CRI-O are not used. In addition to or replacement of this policy, preventing users from mounting …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/disallow-cri-sock-mount/disallow-cri-sock-mount.yaml)

### Privileged containers  
_1 rules · tools: kubescape_

- `kubescape` **C-0213** · HIGH · CIS cis-aks-t1.2.0:4.2.1; cis-aks-t1.8.0:4.2.1 — Minimize the admission of privileged containers
  - _What:_ Do not generally permit containers to be run with the `securityContext.privileged` flag set to `true`.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.privileged` field is set to `false`.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0213-minimizetheadmissionofprivilegedcontainers.json)

### Root group / fsGroup  
_1 rules · tools: kyverno_

- `kyverno` **require-non-root-groups** · MEDIUM — Require Non-Root Groups
  - _What:_ Containers should be forbidden from running with a root primary or supplementary GID. This policy ensures the `runAsGroup`, `supplementalGroups`, and `fsGroup` fields are set to a number greater than zero (i.e., non root). A known issue prevents a policy such as this using `anyPattern` from being persisted properly in Kubernetes 1.23.0-1.23.2.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-non-root-groups/require-non-root-groups.yaml)

### TLS / certificates / ciphers  
_2 rules · tools: kubescape_

- `kubescape` **C-0245** · HIGH · CIS cis-aks-t1.2.0:5.4.5; cis-aks-t1.8.0:5.4.5 — Encrypt traffic to HTTPS load balancers with TLS certificates
  - _What:_ Encrypt traffic to HTTPS load balancers using TLS certificates.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0245-encrypttraffictohttpsloadbalancerswithtlscertificates.json)
- `kubescape` **C-0231** · MEDIUM · CIS cis-eks-t1.7.0:5.4.5; cis-eks-t1.8.0:5.4.5; cis-gke-v1.9.0:5.6.7 — Encrypt traffic to HTTPS load balancers with TLS certificates
  - _What:_ Encrypt traffic to HTTPS load balancers using TLS certificates.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0231-encrypttraffictohttpsloadbalancerswithtlscertificates.json)

### Other  
_10 rules · tools: kubescape, kyverno_

- `kubescape` **C-0228** · HIGH · CIS cis-eks-t1.7.0:5.4.2; cis-eks-t1.8.0:5.4.2; cis-gke-v1.9.0:5.6.4 — Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled
  - _What:_ Disable access to the Kubernetes API from outside the node network if it is not required.
  - _Fix:_ By enabling private endpoint access to the Kubernetes API server, all communication between your nodes and the API server stays within your VPC. With this in mind, you can update your cluster accordingly using the AWS CLI to ensure that Private Endpoint Access is enabled. For example, the …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0228-ensureclustersarecreatedwithprivateendpointenabledandpublicaccessdisabled.json)
- `kubescape` **C-0229** · HIGH · CIS cis-eks-t1.7.0:5.4.3; cis-eks-t1.8.0:5.4.3; cis-gke-v1.9.0:5.6.5 — Ensure clusters are created with Private Nodes
  - _What:_ Disable public IP addresses for cluster nodes, so that they only have private IP addresses. Private Nodes are nodes with no public IP addresses.
  - _Fix:_ ``` aws eks update-cluster-config \ --region region-code \ --name my-cluster \ --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs="203.0.113.5/32",endpointPrivateAccess=true ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0229-ensureclustersarecreatedwithprivatenodes.json)
- `kubescape` **C-0241** · HIGH · CIS cis-aks-t1.2.0:5.2.2; cis-aks-t1.8.0:5.2.2 — Use Azure RBAC for Kubernetes Authorization.
  - _What:_ The ability to manage RBAC for Kubernetes resources from Azure gives you the choice to manage RBAC for the cluster resources either using Azure or native Kubernetes mechanisms.
  - _Fix:_ Set Azure RBAC as access system.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0241-useazurerbacforkubernetesauthorization.json)
- `kubescape` **C-0247** · HIGH · CIS cis-aks-t1.2.0:5.4.1; cis-aks-t1.8.0:5.4.1 — Restrict Access to the Control Plane Endpoint
  - _What:_ Enable Endpoint Private Access to restrict access to the cluster's control plane to only an allowlist of authorized IPs.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0247-restrictaccesstothecontrolplaneendpoint.json)
- `kubescape` **C-0248** · HIGH · CIS cis-aks-t1.2.0:5.4.3; cis-aks-t1.8.0:5.4.3 — Ensure clusters are created with Private Nodes
  - _What:_ Disable public IP addresses for cluster nodes, so that they only have private IP addresses. Private Nodes are nodes with no public IP addresses.
  - _Fix:_ ``` az aks create \ --resource-group <private-cluster-resource-group> \ --name <private-cluster-name> \ --load-balancer-sku standard \ --enable-private-cluster \ --network-plugin azure \ --vnet-subnet-id <subnet-id> \ --docker-bridge-address \ --dns-service-ip \ --service-cidr ``` Where …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0248-ensureclustersarecreatedwithprivatenodes.json)
- `kubescape` **C-0252** · HIGH · CIS cis-aks-t1.2.0:5.4.2; cis-aks-t1.8.0:5.4.2 — Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled
  - _What:_ Disable access to the Kubernetes API from outside the node network if it is not required.
  - _Fix:_ To use a private endpoint, create a new private endpoint in your virtual network then create a link between your virtual network and a new private DNS zone
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0252-ensureclustersarecreatedwithprivateendpointenabledandpublicaccessdisabled.json)
- `kubescape` **C-0221** · MEDIUM · CIS cis-eks-t1.7.0:5.1.1; cis-eks-t1.8.0:5.1.1; cis-gke-v1.9.0:5.1.1 — Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider
  - _What:_ Scan images being deployed to Amazon EKS for vulnerabilities.
  - _Fix:_ To utilize AWS ECR for Image scanning please follow the steps below: To create a repository configured for scan on push (AWS CLI) ``` aws ecr create-repository --repository-name $REPO_NAME --image-scanning-configuration scanOnPush=true --region $REGION_CODE ``` To edit the settings of an existing …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0221-ensureimagevulnerabilityscanningusingamazonecrimagescanningorathirdpartyprovider.json)
- `kubescape` **C-0222** · MEDIUM · CIS cis-eks-t1.7.0:5.1.2; cis-eks-t1.8.0:5.1.2 — Minimize user access to Amazon ECR
  - _What:_ Restrict user access to Amazon ECR, limiting interaction with build images to only authorized personnel and service accounts.
  - _Fix:_ Before you use IAM to manage access to Amazon ECR, you should understand what IAM features are available to use with Amazon ECR. To get a high-level view of how Amazon ECR and other AWS services work with IAM, see AWS Services That Work with IAM in the IAM User Guide. **Topics** * Amazon ECR …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0222-minimizeuseraccesstoamazonecr.json)
- `kyverno` **prevent-bare-pods** · MEDIUM — Prevent Bare Pods
  - _What:_ Pods not created by workload controllers such as Deployments have no self-healing or scaling abilities and are unsuitable for production. This policy prevents such "bare" Pods from being created unless they originate from a higher-level workload controller of some sort.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/prevent-bare-pods/prevent-bare-pods.yaml)
- `kyverno` **require-pod-priorityclassname** · MEDIUM — Require Pod priorityClassName
  - _What:_ A Pod may optionally specify a priorityClassName which indicates the scheduling priority relative to others. This requires creation of a PriorityClass object in advance. With this created, a Pod may set this field to that value. In a multi-tenant environment, it is often desired to require this priorityClassName be set to make certain tenant scheduling guarantees. This policy requires that a Pod …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-pod-priorityclassname/require-pod-priorityclassname.yaml)


## Namespaces & multi-tenancy

### Cloud metadata / IAM  
_2 rules · tools: kyverno, polaris_

- `kyverno` **metadata-match-regex** · MEDIUM — Metadata Matches Regex
  - _What:_ Rather than a simple check to see if given metadata such as labels and annotations are present, in some cases they need to be present and the values match a specified regular expression. This policy illustrates how to ensure a label with key `corp.org/version` is both present and matches a given regex, in this case ensuring semver is met.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/metadata-match-regex/metadata-match-regex.yaml)
- `polaris` **metadataAndInstanceMismatched** · MEDIUM — Label app.kubernetes.io/instance must match metadata.name
  - _What:_ Pass: Label app.kubernetes.io/instance matches metadata.name | Fail: Label app.kubernetes.io/instance must match metadata.name
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/metadataAndInstanceMismatched.yaml)

### Default namespace usage  
_5 rules · tools: kube-bench, kube-linter, kubescape, kyverno, trivy_

- `kyverno` **disallow-default-namespace** · MEDIUM — Disallow Default Namespace in VPOL
  - _What:_ Kubernetes Namespaces are an optional feature that provide a way to segment and isolate cluster resources across multiple applications and users. As a best practice, workloads should be isolated with Namespaces. Namespaces should be required and the default (empty) Namespace should not be used. This policy validates that Pods specify a Namespace name other than `default`. Rule auto-generation is …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/disallow-default-namespace/disallow-default-namespace.yaml)
- `kubescape` **C-0061** · LOW — Pods in default namespace
  - _What:_ It is recommended to avoid running pods in cluster without explicit namespace assignment. This control identifies all the pods running in the default namespace.
  - _Fix:_ Create necessary namespaces and move all the pods from default namespace there.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0061-podsindefaultnamespace.json)
- `trivy` **KSV-0110** · LOW — Workloads in the default namespace
  - _What:_ Checks whether a workload is running in the default namespace.
  - _Fix:_ Set 'metadata.namespace' to a non-default namespace.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/default_namespace_should_not_be_used.rego)
- `kube-bench` **5.6.4** · manual · CIS cis-1.11:5.6.4 — The default namespace should not be used
  - _What:_ [General Policies] The default namespace should not be used
  - _Fix:_ Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **use-namespace** · CIS cis:5.7.1; cis:5.7.4 — Use namespace
  - _What:_ Indicates when a resource is deployed to the default namespace. CIS Benchmark 5.7.1: Create administrative boundaries between resources using namespaces. CIS Benchmark 5.7.4: The default namespace should not be used.
  - _Fix:_ Create namespaces for objects in your deployment.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/usenamespace.yaml)

### Other  
_17 rules · tools: gatekeeper, kube-bench, kube-linter, kubescape, kyverno, trivy_

- `trivy` **KSV-0112** · CRITICAL — Manage all resources at the namespace
  - _What:_ Full control of the resources within a namespace. In some cluster configurations, this is excessive. In others, this is normal (a gitops deployment operator like flux)
  - _Fix:_ Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by role in namespace
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_all_resources_at_namespace.rego)
- `kubescape` **C-0209** · MEDIUM · CIS cis-aks-t1.2.0:4.7.1; cis-aks-t1.8.0:4.7.1; cis-eks-t1.7.0:4.5.1; cis-eks-t1.8.0:4.5.1; cis-gke-v1.9.0:4.6.1; cis-v1.10.0:5.7.1; cis-v1.12.0:5.6.1 — Create administrative boundaries between resources using namespaces
  - _What:_ Use namespaces to isolate your Kubernetes objects.
  - _Fix:_ Follow the documentation and create namespaces for objects in your deployment as you need them.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0209-createadministrativeboundariesbetweenresourcesusingnamespaces.json)
- `kyverno` **allowed-annotations** · MEDIUM — Allowed Annotations
  - _What:_ Rather than creating a deny list of annotations, it may be more useful to invert that list and create an allow list which then denies any others. This policy demonstrates how to allow two annotations with a specific key name of fluxcd.io/ while denying others that do not meet the pattern.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/allowed-annotations/allowed-annotations.yaml)
- `kyverno` **exclude-namespaces-example** · MEDIUM — Exclude Namespaces Dynamically
  - _What:_ It's common where policy lookups need to consider a mapping to many possible values rather than a static mapping. This is a sample which demonstrates how to dynamically look up an allow list of Namespaces from a ConfigMap where the ConfigMap stores an array of strings. This policy validates that any Pods created outside of the list of Namespaces have the label `foo` applied.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/exclude-namespaces-dynamically/exclude-namespaces-dynamically.yaml)
- `kyverno` **require-annotations** · MEDIUM — Require Annotations
  - _What:_ Define and use annotations that identify semantic attributes of your application or Deployment. A common set of annotations allows tools to work collaboratively, describing objects in a common manner that all tools can understand. The recommended annotations describe applications in a way that can be queried. This policy validates that the annotation `corp.org/department` is specified with some …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-annotations/require-annotations.yaml)
- `kyverno` **validate-initdata-configmap** · MEDIUM — Validate InitData ConfigMap Required Fields
  - _What:_ Validates that ConfigMaps with a label key "coco.io/type" and value "initdata" contain all required fields with proper values.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/validate-initdata-configmap/validate-initdata-configmap.yaml)
- `trivy` **KSV-0037** · MEDIUM — User resources should not be placed in kube-system namespace
  - _What:_ ensure that user resources are not placed in kube-system namespace
  - _Fix:_ Deploy the user resources into a designated namespace which is not kube-system.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/protect_core_components_namespace.rego)
- `kubescape` **C-0076** · LOW — Label usage for resources
  - _What:_ It is recommended to set labels that identify semantic attributes of your application or deployment. For example, { app: myapp, tier: frontend, phase: test, deployment: v3 }. These labels can used to assign policies to logical groups of the deployments as well as for presentation and tracking purposes. This control helps you find deployments without any of the expected labels.
  - _Fix:_ Define labels that are most suitable to your needs of use the exceptions to prevent further notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0076-labelusageforresources.json)
- `kubescape` **C-0296** · LOW — Mismatching selector
  - _What:_ A workload selector that does not match its pod template labels can prevent the controller from managing the intended pods. This usually results from label drift or copy-paste mistakes.
  - _Fix:_ Update spec.selector, spec.jobTemplate.spec.selector, or the pod template labels so the selector matches the pod template labels.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0296-mismatchingselector.json)
- `gatekeeper` **k8srequiredannotations** — Required Annotations
  - _What:_ Requires resources to contain specified annotations, with values matching provided regular expressions.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/requiredannotations/template.yaml)
- `gatekeeper` **k8srequiredlabels** — Required Labels
  - _What:_ Requires resources to contain specified labels, with values matching provided regular expressions.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/requiredlabels/template.yaml)
- `kube-bench` **5.6.1** · manual · CIS cis-1.11:5.6.1 — Create administrative boundaries between resources using namespaces
  - _What:_ [General Policies] Create administrative boundaries between resources using namespaces
  - _Fix:_ Follow the documentation and create namespaces for objects in your deployment as you need them.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **mismatching-selector** — Mismatching selector
  - _What:_ Indicates when deployment selectors fail to match the pod template labels.
  - _Fix:_ Confirm that your deployment selector correctly matches the labels in its pod template.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/mismatching-selector.yaml)
- `kube-linter` **required-annotation-email** — Required annotation email
  - _What:_ Indicates when objects do not have an email annotation with a valid email address.
  - _Fix:_ Add an email annotation to your object with the email address of the object's owner.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/required-annotation-email.yaml)
- `kube-linter` **required-label-owner** — Required label owner
  - _What:_ Indicates when objects do not have an email annotation with an owner label.
  - _Fix:_ Add an email annotation to your object with the name of the object's owner.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/required-label-owner.yaml)
- `kyverno` **pod-lifetime** — Enforce pod duration
  - _What:_ This validation is valuable when annotations are used to define durations, such as to ensure a Pod lifetime annotation does not exceed some site specific max threshold. Pod lifetime annotation can be no greater than 8 hours.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/enforce-pod-duration/enforce-pod-duration.yaml)
- `kyverno` **restrict-annotations** — Restrict Annotations
  - _What:_ Some annotations control functionality driven by other cluster-wide tools and are not normally set by some class of users. This policy prevents the use of an annotation beginning with `fluxcd.io/`. This can be useful to ensure users either don't set reserved annotations or to force them to use a newer version of an annotation.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-annotations/restrict-annotations.yaml)


## Network security

### CPU/memory limits & requests  
_2 rules · tools: kyverno_

- `kyverno` **require-qos-burstable** · MEDIUM — Require QoS Burstable
  - _What:_ Pod Quality of Service (QoS) is a mechanism to ensure Pods receive certain priority guarantees based upon the resources they define. When a Pod has at least one container which defines either requests or limits for either memory or CPU, Kubernetes grants the QoS class as burstable if it does not otherwise qualify for a QoS class of guaranteed. This policy requires that a Pod meet the criteria …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-qos-burstable/require-qos-burstable.yaml)
- `kyverno` **require-qos-guaranteed** · MEDIUM — Require QoS Guaranteed
  - _What:_ Pod Quality of Service (QoS) is a mechanism to ensure Pods receive certain priority guarantees based upon the resources they define. When Pods define both requests and limits for both memory and CPU, and the requests and limits are equal to each other, Kubernetes grants the QoS class as guaranteed which allows them to run at a higher priority than others. This policy requires that all containers …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-qos-guaranteed/require-qos-guaranteed.yaml)

### File permissions / ownership  
_1 rules · tools: kubescape_

- `kubescape` **C-0037** · MEDIUM — CoreDNS poisoning
  - _What:_ If attackers have permissions to modify the coredns ConfigMap they can change the behavior of the cluster’s DNS, poison it, and override the network identity of other services. This control identifies all subjects allowed to update the 'coredns' configmap.
  - _Fix:_ You should follow the least privilege principle. Monitor and approve all the subjects allowed to modify the 'coredns' configmap. It is also recommended to remove this permission from the users/service accounts used in the daily operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0037-corednspoisoning.json)

### Host network  
_1 rules · tools: gatekeeper_

- `gatekeeper` **k8spsphostnetworkingports** — Host Networking Ports
  - _What:_ Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific ports must be specified. Corresponds to the `hostNetwork` and `hostPorts` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/host-network-ports/template.yaml)

### Host ports  
_7 rules · tools: checkov, kube-bench, kubescape, kyverno, polaris, trivy_

- `trivy` **KSV-0024** · HIGH — Access to host ports
  - _What:_ According to pod security standard 'Host Ports', hostPorts should be disallowed, or at minimum restricted to a known list.
  - _Fix:_ Do not set spec.containers[*].ports[*].hostPort and spec.initContainers[*].ports[*].hostPort.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/access_to_host_ports.rego)
- `kubescape` **C-0044** · MEDIUM — Container hostPort
  - _What:_ Configuring hostPort requires a particular port number. If two objects specify the same HostPort, they could not be deployed to the same node. It may prevent the second object from starting, even if Kubernetes will try reschedule it on another node, provided there are available nodes with sufficient amount of resources. Also, if the number of replicas of such workload is higher than the number …
  - _Fix:_ Avoid usage of hostPort unless it is absolutely necessary, in which case define appropriate exception. Use NodePort / ClusterIP instead.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0044-containerhostport.json)
- `kubescape` **C-0204** · MEDIUM · CIS cis-v1.10.0:5.2.13; cis-v1.12.0:5.2.12 — Minimize the admission of containers which use HostPorts
  - _What:_ Do not generally permit containers which require the use of HostPorts.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers which use `hostPort` sections.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0204-minimizetheadmissionofcontainerswhichusehostports.json)
- `kyverno` **disallow-host-ports** · MEDIUM — Disallow hostPorts
  - _What:_ Access to host ports allows potential snooping of network traffic and should not be allowed, or at minimum restricted to a known list. This policy ensures the `hostPort` field is unset or set to `0`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-host-ports/disallow-host-ports.yaml)
- `polaris` **hostPortSet** · MEDIUM — Host port should not be configured
  - _What:_ Pass: Host port is not configured | Fail: Host port should not be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostPortSet.yaml)
- `checkov` **CKV_K8S_26** — Do not specify hostPort unless absolutely necessary
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/HostPort.py)
- `kube-bench` **5.2.13** · manual · CIS cis-1.11:5.2.13 — Minimize the admission of containers which use HostPorts
  - _What:_ [Pod Security Standards] Minimize the admission of containers which use HostPorts
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers which use `hostPort` sections.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### Ingress configuration  
_19 rules · tools: gatekeeper, kube-linter, kubescape, kyverno, polaris, trivy_

- `trivy` **KCV-0093** · CRITICAL — Ensure ingress-nginx annotations are secure
  - _What:_ Check for insecure annotations in ingress-nginx configurations.
  - _Fix:_ Ensure that ingress-nginx annotations do not contain suspicious characters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/insecure_ingress_nginx.rego)
- `kubescape` **C-0263** · HIGH — Ingress uses TLS
  - _What:_ This control detect Ingress resources that do not use TLS
  - _Fix:_ The user needs to implement TLS for the Ingress resource in order to encrypt the incoming traffic
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0263-ingress-tls.json)
- `kubescape` **C-0266** · HIGH — Exposure to internet via Gateway API or Istio Ingress
  - _What:_ This control detect workloads that are exposed on Internet through a Gateway API (HTTPRoute,TCPRoute, UDPRoute) or Istio Gateway. It fails in case it find workloads connected with these resources.
  - _Fix:_ The user can evaluate its exposed resources and apply relevant changes wherever needed.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0266-exposuretointernet-gateway.json)
- `kyverno` **check-ingress-nginx-controller-version-and-annotation-policy** · HIGH — Ensure Valid Ingress NGINX Controller and Annotations
  - _What:_ This policy ensures that Ingress resources do not have certain disallowed annotations and that the ingress-nginx controller Pod is running an appropriate version of the image. It checks for the presence of the `nginx.ingress.kubernetes.io/server-snippet` annotation and disallows its usage, enforces specific values for `auth-tls-verify-client`, and ensures that the ingress-nginx controller image …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-ingress-nginx-controller-version-and-annotation-policy/check-ingress-nginx-controller-version-and-annotation-policy.yaml)
- `kyverno` **restrict-ingress-defaultbackend** · HIGH — Restrict Ingress defaultBackend
  - _What:_ An Ingress with no rules sends all traffic to a single default backend. The defaultBackend is conventionally a configuration option of the Ingress controller and is not specified in your Ingress resources. If none of the hosts or paths match the HTTP request in the Ingress objects, the traffic is routed to your default backend. In a multi-tenant environment, you want users to use explicit hosts, …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-ingress-defaultbackend/restrict-ingress-defaultbackend.yaml)
- `kubescape` **C-0030** · MEDIUM — Ingress and Egress blocked
  - _What:_ Disable Ingress and Egress traffic on all pods wherever possible. It is recommended to define restrictive network policy on all new pods, and then enable sources/destinations that this pod must communicate with.
  - _Fix:_ Define a NetworkPolicy, CiliumNetworkPolicy, or CiliumClusterwideNetworkPolicy that restricts ingress and egress connections.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0030-ingressandegressblocked.json)
- `kubescape` **C-0292** · MEDIUM — Nginx Ingress Controller End of Life
  - _What:_ The nginx ingress controller project reaches End of Life (EOL) in March 2026. After this date, no security patches or functional updates will be provided. This control identifies workloads using nginx ingress controllers to help users plan migration to supported alternatives.
  - _Fix:_ Migrate to a supported ingress controller solution: 1) F5 NGINX Ingress Controller (https://docs.nginx.com/nginx-ingress-controller/) for a supported NGINX-based option, 2) Kubernetes Gateway API for a cloud-native approach, 3) HAProxy Ingress, 4) Traefik, 5) Cloud-native solutions (AWS ALB …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0292-nginx-ingress-controller-eol.json)
- `kubescape` **C-0298** · MEDIUM — Dangling Ingress backend
  - _What:_ An Ingress whose backend references a Service that does not exist in the same namespace produces broken routing with no traffic. It typically results from a Service being renamed, deleted, or a typo in the backend service name.
  - _Fix:_ Create the referenced Service or correct the Ingress backend service name.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0298-danglingingressbackend.json)
- `kyverno` **disallow-empty-ingress-host** · MEDIUM — Disallow empty Ingress host in VPOL
  - _What:_ An ingress resource needs to define an actual host name in order to be valid. This policy ensures that there is a hostname for each rule defined.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/disallow-empty-ingress-host/disallow-empty-ingress-host.yaml)
- `kyverno` **ingress-host-match-tls** · MEDIUM — Ingress Host Match TLS
  - _What:_ Ingress resources which name a host name that is not present in the TLS section can produce ingress routing failures as a TLS certificate may not correspond to the destination host. This policy ensures that the host name in an Ingress rule is also found in the list of TLS hosts.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/ingress-host-match-tls/ingress-host-match-tls.yaml)
- `kyverno` **no-localhost-service** · MEDIUM — Disallow Localhost ExternalName Services
  - _What:_ A Service of type ExternalName which points back to localhost can potentially be used to exploit vulnerabilities in some Ingress controllers. This policy audits Services of type ExternalName if the externalName field refers to localhost.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/disallow-localhost-services/disallow-localhost-services.yaml)
- `kyverno` **require-ingress-https** · MEDIUM — Require Ingress HTTPS
  - _What:_ Ingress resources should only allow secure traffic by disabling HTTP and therefore only allowing HTTPS. This policy requires that all Ingress resources set the annotation `kubernetes.io/ingress.allow-http` to `"false"` and specify TLS in the spec.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-ingress-https/require-ingress-https.yaml)
- `kyverno` **restrict-ingress-classes** · MEDIUM — Restrict Ingress Classes
  - _What:_ Ingress classes should only be allowed which match up to deployed Ingress controllers in the cluster. Allowing users to define classes which cannot be satisfied by a deployed Ingress controller can result in either no or undesired functionality. This policy checks Ingress resources and only allows those which define `HAProxy` or `nginx` in the respective annotation. This annotation has largely …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-ingress-classes/restrict-ingress-classes.yaml)
- `kyverno` **restrict-ingress-wildcard** · MEDIUM — Restrict Ingress Host with Wildcards
  - _What:_ Ingress hosts optionally accept a wildcard as an alternative to precise matching. In some cases, this may be too permissive as it would direct unintended traffic to the given Ingress resource. This policy enforces that any Ingress host does not contain a wildcard character.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-ingress-wildcard/restrict-ingress-wildcard.yaml)
- `kyverno` **unique-ingress-path** · MEDIUM — Unique Ingress Path
  - _What:_ Just like the need to ensure uniqueness among Ingress hosts, there is a need to have the paths be unique as well. This policy checks an incoming Ingress to ensure its root path does not conflict with another root path in a different Namespace. It requires that incoming Ingress resources have a single rule with a single path only and assumes the root path is specified explicitly in an existing …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/unique-ingress-paths/unique-ingress-paths.yaml)
- `polaris` **tlsSettingsMissing** · MEDIUM — Ingress does not have TLS configured
  - _What:_ Pass: Ingress has TLS configured | Fail: Ingress does not have TLS configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/tlsSettingsMissing.yaml)
- `gatekeeper` **k8sblockwildcardingress** — Block Wildcard Ingress
  - _What:_ Users should not be able to create Ingresses with a blank or wildcard (*) hostname since that would enable them to intercept traffic for other services in the cluster, even if they don't have access to those services.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/block-wildcard-ingress/template.yaml)
- `gatekeeper` **k8suniqueingresshost** — Unique Ingress Host
  - _What:_ Requires all Ingress rule hosts to be unique. Does not handle hostname wildcards: https://kubernetes.io/docs/concepts/services-networking/ingress/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/uniqueingresshost/template.yaml)
- `kube-linter` **dangling-ingress** — Dangling ingress
  - _What:_ Indicates when ingress do not have any associated services.
  - _Fix:_ Confirm that your ingress's backend correctly matches the name and port on one of your services.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-ingress.yaml)

### Liveness / readiness probes  
_1 rules · tools: kubescape_

- `kubescape` **C-0049** · LOW — Network mapping
  - _What:_ If no network policy is defined, attackers who gain access to a single container may use it to probe the network. This control lists all namespaces in which no network policies (NetworkPolicy, CiliumNetworkPolicy, or qualifying CiliumClusterwideNetworkPolicy) are defined.
  - _Fix:_ Define NetworkPolicy, CiliumNetworkPolicy, or CiliumClusterwideNetworkPolicy resources, or use similar network protection mechanisms.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0049-networkmapping.json)

### Network policies  
_16 rules · tools: checkov, kube-bench, kube-linter, kubescape, polaris, trivy_

- `kubescape` **C-0314** · HIGH — Agent Sandbox managed network policy
  - _What:_ SandboxTemplate networking should remain controller-managed. The managed default blocks private and internal destinations but still permits public internet; it is not strict default-deny egress.
  - _Fix:_ Set spec.networkPolicyManagement to Managed or omit it to use the API default. Use the separate strict-egress control when public internet must also be denied.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0314-agent-sandbox-managed-networking.json)
- `kubescape` **C-0315** · HIGH — Agent Sandbox strict egress policy
  - _What:_ When agentSandboxEgressMode is strict, SandboxTemplate must carry an explicit managed NetworkPolicy with no egress rules. The ordinary managed default still allows public internet and does not satisfy this control.
  - _Fix:_ Keep networkPolicyManagement Managed and explicitly set spec.networkPolicy.egress to an empty list. This mode does not permit any egress destinations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0315-agent-sandbox-strict-egress.json)
- `trivy` **KSV-0056** · HIGH — Manage Kubernetes networking
  - _What:_ The ability to control which pods get service traffic directed to them allows for interception attacks. Controlling network policy allows for bypassing lateral movement restrictions.
  - _Fix:_ Networking resources are only allowed for verbs 'list', 'watch', 'get'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_kubernetes_networking.rego)
- `kubescape` **C-0054** · MEDIUM — Cluster internal networking
  - _What:_ If no network policy is defined, attackers who gain access to a container may use it to move laterally in the cluster. This control lists namespaces in which no network policy (NetworkPolicy, CiliumNetworkPolicy, or qualifying CiliumClusterwideNetworkPolicy) is defined.
  - _Fix:_ Define Kubernetes NetworkPolicy, CiliumNetworkPolicy, or CiliumClusterwideNetworkPolicy resources to protect cluster network.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0054-clusterinternalnetworking.json)
- `kubescape` **C-0205** · MEDIUM · CIS cis-aks-t1.2.0:4.4.1; cis-aks-t1.8.0:4.4.1; cis-eks-t1.7.0:4.3.1; cis-eks-t1.8.0:4.3.1; cis-gke-v1.9.0:4.3.1; cis-v1.10.0:5.3.1; cis-v1.12.0:5.3.1 — Ensure that the CNI in use supports Network Policies
  - _What:_ There are a variety of CNI plugins available for Kubernetes. If the CNI in use does not support Network Policies it may not be possible to effectively restrict traffic in the cluster.
  - _Fix:_ If the CNI plugin in use does not support network policies, consideration should be given to making use of a different plugin, or finding an alternate mechanism for restricting traffic in the Kubernetes cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0205-ensurethatthecniinusesupportsnetworkpolicies.json)
- `kubescape` **C-0206** · MEDIUM · CIS cis-aks-t1.2.0:4.4.2; cis-aks-t1.8.0:4.4.2; cis-eks-t1.7.0:4.3.2; cis-eks-t1.8.0:4.3.2; cis-gke-v1.9.0:4.3.2; cis-v1.10.0:5.3.2; cis-v1.12.0:5.3.2 — Ensure that all Namespaces have Network Policies defined
  - _What:_ Use network policies to isolate traffic in your cluster network.
  - _Fix:_ Follow the documentation and create `NetworkPolicy`, `CiliumNetworkPolicy`, or `CiliumClusterwideNetworkPolicy` objects as you need them.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0206-ensurethatallnamespaceshavenetworkpoliciesdefined.json)
- `kubescape` **C-0260** · MEDIUM — Missing network policy
  - _What:_ This control detects workloads that has no NetworkPolicy configured in labels. If a network policy is not configured, it means that your applications might not have necessary control over the traffic to and from the pods, possibly leading to a security vulnerability.
  - _Fix:_ Review the workloads identified by this control and assess whether it's necessary to configure a network policy for them.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0260-missingnetworkpolicy.json)
- `kubescape` **C-0299** · MEDIUM — Dangling NetworkPolicy
  - _What:_ A NetworkPolicy whose podSelector matches no workload in the same namespace gives a false sense of isolation — the policy exists but protects nothing.
  - _Fix:_ Verify the NetworkPolicy podSelector matches the labels of at least one workload in the same namespace, or remove the policy.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0299-danglingnetworkpolicy.json)
- `polaris` **missingNetworkPolicy** · MEDIUM — A NetworkPolicy should match pod labels and contain applied egress and ingress rules
  - _What:_ Pass: A NetworkPolicy matches pod labels and contains egress and ingress rules | Fail: A NetworkPolicy should match pod labels and contain applied egress and ingress rules
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/missingNetworkPolicy.yaml)
- `trivy` **KSV-0038** · MEDIUM — Selector usage in network policies
  - _What:_ ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network
  - _Fix:_ create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/selector_usage_in_network_policies.rego)
- `checkov` **CKV2_K8S_6** — Minimize the admission of pods which lack an associated NetworkPolicy
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/RequireAllPodsToHaveNetworkPolicy.yaml)
- `kube-bench` **5.3.1** · manual · CIS cis-1.11:5.3.1 — Ensure that the CNI in use supports NetworkPolicies
  - _What:_ [Network Policies and CNI] Ensure that the CNI in use supports NetworkPolicies
  - _Fix:_ If the CNI plugin in use does not support network policies, consideration should be given to making use of a different plugin, or finding an alternate mechanism for restricting traffic in the Kubernetes cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.3.2** · manual · CIS cis-1.11:5.3.2 — Ensure that all Namespaces have NetworkPolicies defined
  - _What:_ [Network Policies and CNI] Ensure that all Namespaces have NetworkPolicies defined
  - _Fix:_ Follow the documentation and create NetworkPolicy objects as you need them.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **dangling-networkpolicy** — Dangling networkpolicy
  - _What:_ Indicates when networkpolicies do not have any associated deployments.
  - _Fix:_ Confirm that your networkPolicy's podselector correctly matches the labels on one of your deployments.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-networkpolicy.yaml)
- `kube-linter` **dangling-networkpolicypeer-podselector** — Dangling networkpolicypeer podselector
  - _What:_ Indicates when NetworkPolicyPeer in Egress/Ingress rules -in the Spec of NetworkPolicy- do not have any associated deployments. Applied on peer specified with podSelectors only.
  - _Fix:_ Confirm that your NetworkPolicy's Ingress/Egress peer's podselector correctly matches the labels on one of your deployments.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-networkpolicypeer-podselector.yaml)
- `kube-linter` **non-isolated-pod** — Non isolated pod
  - _What:_ Alert on deployment-like objects that are not selected by any NetworkPolicy.
  - _Fix:_ Ensure pod does not accept unsafe traffic by isolating it with a NetworkPolicy. See https://cloud.redhat.com/blog/guide-to-kubernetes-ingress-network-policies for more details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/non-isolated-pod.yaml)

### NodePort / LoadBalancer / external exposure  
_10 rules · tools: gatekeeper, kube-linter, kubescape, kyverno_

- `kubescape` **C-0083** · HIGH — Workloads with Critical vulnerabilities exposed to external traffic
  - _What:_ Container images with known critical vulnerabilities pose elevated risk if they are exposed to the external traffic. This control lists all images with such vulnerabilities if either LoadBalancer or NodePort service is assigned to them.
  - _Fix:_ Either update the container image to fix the vulnerabilities (if such fix is available) or reassess if this workload must be exposed to the outseide traffic. If no fix is available, consider periodic restart of the pod to minimize the risk of persistant intrusion. Use exception mechanism if you …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0083-workloadswithcriticalvulnerabilitiesexposedtoexternaltraffic.json)
- `kubescape` **C-0084** · HIGH — Workloads with RCE vulnerabilities exposed to external traffic
  - _What:_ Container images with known Remote Code Execution (RCE) vulnerabilities pose significantly higher risk if they are exposed to the external traffic. This control lists all images with such vulnerabilities if their pod has either LoadBalancer or NodePort service.
  - _Fix:_ Either update the container image to fix the vulnerabilities (if such fix is available) or reassess if this workload must be exposed to the outseide traffic. If no fix is available, consider periodic restart of the pod to minimize the risk of persistant intrusion. Use exception mechanism if you …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0084-workloadswithrcevulnerabilitiesexposedtoexternaltraffic.json)
- `kubescape` **C-0256** · HIGH — External facing
  - _What:_ This control detect workloads that are exposed on Internet through a Service (NodePort or LoadBalancer) or Ingress. It fails in case it find workloads connected with these resources.
  - _Fix:_ The user can evaluate its exposed resources and apply relevant changes wherever needed.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0256-exposuretointernet.json)
- `kyverno` **no-loadbalancer-service** · MEDIUM — Disallow Service Type LoadBalancer
  - _What:_ Especially in cloud provider environments, a Service having type LoadBalancer will cause the provider to respond by creating a load balancer somewhere in the customer account. This adds cost and complexity to a deployment. Without restricting this ability, users may easily overrun established budgets and security practices set by the organization. This policy restricts use of the Service type …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-loadbalancer/restrict-loadbalancer.yaml)
- `kyverno` **restrict-external-ips** · MEDIUM — Restrict External IPs
  - _What:_ This policy restricts the use of externalIPs in Service resources. External IPs can pose security risks and should be carefully controlled.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/restrict-service-external-ips/restrict-service-external-ips.yaml)
- `kyverno` **restrict-nodeport** · MEDIUM — Restrict NodePort Services
  - _What:_ This policy restricts the creation of Services with type NodePort. NodePort services expose applications on a static port on each node, which can pose security risks and complicate network management.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/restrict-node-port/restrict-node-port.yaml)
- `gatekeeper` **k8sblockloadbalancer** — Block Services with type LoadBalancer
  - _What:_ Disallows all Services with type LoadBalancer. https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/block-loadbalancer-services/template.yaml)
- `gatekeeper` **k8sblocknodeport** — Block NodePort
  - _What:_ Disallows all Services with type NodePort. https://kubernetes.io/docs/concepts/services-networking/service/#nodeport
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/block-nodeport-services/template.yaml)
- `gatekeeper` **k8sexternalips** — External IPs
  - _What:_ Restricts Service externalIPs to an allowed list of IP addresses. https://kubernetes.io/docs/concepts/services-networking/service/#external-ips
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/externalip/template.yaml)
- `kube-linter` **exposed-services** — Exposed services
  - _What:_ Alert on services for forbidden types
  - _Fix:_ Ensure containers are not exposed through a forbidden service type such as NodePort or LoadBalancer.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/servicetype.yaml)

### TLS / certificates / ciphers  
_5 rules · tools: gatekeeper, kube-linter, kubescape_

- `kubescape` **C-0155** · MEDIUM · CIS cis-v1.10.0:2.3; cis-v1.12.0:2.3 — Ensure that the --auto-tls argument is not set to true
  - _What:_ Do not use self-signed certificates for TLS.
  - _Fix:_ Edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and either remove the `--auto-tls` parameter or set it to `false`. ``` --auto-tls=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0155-ensurethattheautotlsargumentisnotsettotrue.json)
- `kubescape` **C-0158** · MEDIUM · CIS cis-v1.10.0:2.6; cis-v1.12.0:2.6 — Ensure that the --peer-auto-tls argument is not set to true
  - _What:_ Do not use automatically generated self-signed certificates for TLS connections between peers.
  - _Fix:_ Edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and either remove the `--peer-auto-tls` parameter or set it to `false`. ``` --peer-auto-tls=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0158-ensurethatthepeerautotlsargumentisnotsettotrue.json)
- `gatekeeper` **k8shttpsonly** — HTTPS Only
  - _What:_ Requires Ingress resources to be HTTPS only. Ingress resources must include the `kubernetes.io/ingress.allow-http` annotation, set to `false`. By default a valid TLS {} configuration is required, this can be made optional by setting the `tlsOptional` parameter to `true`. https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/httpsonly/template.yaml)
- `gatekeeper` **k8suniqueserviceselector** — Unique Service Selector
  - _What:_ Requires Services to have unique selectors within a namespace. Selectors are considered the same if they have identical keys and values. Selectors may share a key/value pair so long as there is at least one distinct key/value pair between them. https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/uniqueserviceselector/template.yaml)
- `kube-linter` **dangling-servicemonitor** — Dangling servicemonitor
  - _What:_ Indicates when a service monitor's selectors don't match any service. ServiceMonitors are a custom resource only used by the Prometheus operator (https://prometheus-operator.dev/docs/operator/design/#servicemonitor).
  - _Fix:_ Check selectors and your services.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-servicemonitor.yaml)

### Other  
_10 rules · tools: kube-linter, kubescape, kyverno_

- `kubescape` **C-0301** · HIGH — Agent Sandbox egress policy enforcement
  - _What:_ Ensure Agent Sandbox SandboxTemplate resources enforce an explicitly scoped egress policy.
  - _Fix:_ Configure SandboxTemplate with an explicitly scoped egress policy.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0301-agentsandboxegresspolicy.json)
- `kubescape` **C-0302** · MEDIUM — Dangling Gateway API backend
  - _What:_ A Gateway API route (HTTPRoute, TCPRoute, UDPRoute) whose backendRef references a Service that does not exist in the target namespace silently routes nowhere. Only Service backends are validated; non-Service backends (custom resources) are skipped.
  - _Fix:_ Create the referenced Service or correct the route backendRef.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0302-danglinggatewaybackend.json)
- `kyverno` **require-container-port-names** · MEDIUM — Require Container Port Names
  - _What:_ Containers may define ports on which they listen. In addition to a port number, a name field may optionally be used. Including a name makes it easier when defining Service resource definitions and others since the name may be referenced allowing the port number to change. This policy requires that for every containerPort defined there is also a name specified.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-container-port-names/require-container-port-names.yaml)
- `kyverno` **restrict-service-port-range** · MEDIUM — Restrict Service Port Range
  - _What:_ Services which are allowed to expose any port number may be able to impact other applications running on the Node which require them, or may make specifying security policy externally more challenging. This policy enforces that only the port range 32000 to 33000 may be used for Service resources.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-service-port-range/restrict-service-port-range.yaml)
- `kyverno` **restrict-storageclass** · MEDIUM — Restrict StorageClass
  - _What:_ StorageClasses allow description of custom "classes" of storage offered by the cluster, based on quality-of-service levels, backup policies, or custom policies determined by the cluster administrators. For shared StorageClasses in a multi-tenancy environment, a reclaimPolicy of `Delete` should be used to ensure a PersistentVolume cannot be reused across Namespaces. This policy requires …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-storageclass/restrict-storageclass.yaml)
- `kubescape` **C-0293** · LOW — Service with no workload
  - _What:_ A Service whose selector does not match any workload pod is dangling. It typically results from a workload being renamed or deleted, or from a typo in the selector or pod labels. Dangling Services consume cluster names and can cause silent routing failures.
  - _Fix:_ Verify the Service selector matches the labels of an existing workload in the same namespace, or remove the Service if it is no longer needed.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0293-servicewithnoworkload.json)
- `kubescape` **C-0305** · LOW — No rolling update strategy
  - _What:_ A Deployment that explicitly uses a non-rolling update strategy can cause avoidable service interruption during workload updates.
  - _Fix:_ Set spec.strategy.type to RollingUpdate.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0305-norollingupdatestrategy.json)
- `kube-linter` **dangling-service** — Dangling service
  - _What:_ Indicates when services do not have any associated deployments.
  - _Fix:_ Confirm that your service's selector correctly matches the labels on one of your deployments.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dangling-service.yaml)
- `kube-linter` **dnsconfig-options** — Dnsconfig options
  - _What:_ Alert on deployments that have no specified dnsConfig options
  - _Fix:_ Specify dnsconfig options in your Pod specification to ensure the expected DNS setting on the Pod. Refer to https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-dns-config for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/dnsconfig-options.yaml)
- `kube-linter` **invalid-target-ports** — Invalid target ports
  - _What:_ Indicates when deployments or services are using port names that are violating specifications.
  - _Fix:_ Ensure that port naming is in conjunction with the specification. For more information, please look at the Kubernetes Service specification on this page: https://kubernetes.io/docs/reference/_print/#ServiceSpec. And additional information about IANA Service naming can be found on the following …
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/invalid-target-ports.yaml)


## RBAC & identity

### API / kubelet authn & authz flags  
_1 rules · tools: kubescape_

- `kubescape` **C-0173** · MEDIUM · CIS cis-aks-t1.2.0:3.2.2; cis-aks-t1.8.0:3.2.2; cis-eks-t1.7.0:3.2.2; cis-eks-t1.8.0:3.2.2; cis-v1.10.0:4.2.2; cis-v1.12.0:4.2.2 — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ Do not allow all requests. Enable explicit authorization.
  - _Fix:_ If using a Kubelet config file, edit the file to set `authorization: mode` to `Webhook`. If using executable arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_AUTHZ_ARGS` variable. ``` --authorization-mode=Webhook …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0173-ensurethattheauthorizationmodeargumentisnotsettoalwaysallow.json)

### Allowed / trusted registries  
_1 rules · tools: kubescape_

- `kubescape` **C-0078** · MEDIUM · CIS cis-aks-t1.2.0:5.1.4; cis-aks-t1.8.0:5.1.4; cis-eks-t1.7.0:5.1.4; cis-eks-t1.8.0:5.1.4; cis-gke-v1.9.0:5.1.4 — Images from allowed registry
  - _What:_ This control is intended to ensure that all the used container images are taken from the authorized repositories. It allows user to list all the approved repositories and will fail all the images taken from any repository outside of this list.
  - _Fix:_ You should enable all trusted repositories in the parameters of this control.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0078-imagesfromallowedregistry.json)

### Default ServiceAccount  
_5 rules · tools: checkov, kube-bench, kube-linter, kubescape_

- `kubescape` **C-0189** · MEDIUM · CIS cis-aks-t1.2.0:4.1.5; cis-aks-t1.8.0:4.1.5; cis-eks-t1.7.0:4.1.5; cis-eks-t1.8.0:4.1.5; cis-gke-v1.9.0:4.1.4; cis-v1.10.0:5.1.5; cis-v1.12.0:5.1.5 — Ensure that default service accounts are not actively used
  - _What:_ The `default` service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed.
  - _Fix:_ Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server. Modify the configuration of each default service account to include this value ``` automountServiceAccountToken: false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0189-ensurethatdefaultserviceaccountsarenotactivelyused.json)
- `checkov` **CKV_K8S_41** · CIS cis-1.5:5.1.5 — Ensure that default service accounts are not actively used
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DefaultServiceAccount.py)
- `checkov` **CKV_K8S_42** · CIS cis-1.5:5.1.5 — Ensure that default service accounts are not actively used
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DefaultServiceAccountBinding.py)
- `kube-bench` **5.1.5** · manual · CIS cis-1.11:5.1.5 — Ensure that default service accounts are not actively used
  - _What:_ [RBAC and Service Accounts] Ensure that default service accounts are not actively used
  - _Fix:_ Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server. Modify the configuration of each default service account to include this value `automountServiceAccountToken: false`.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **default-service-account** — Default service account
  - _What:_ Indicates when pods use the default service account.
  - _Fix:_ Create a dedicated service account for your pod. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/ for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/default-service-account.yaml)

### Default namespace usage  
_2 rules · tools: checkov, kubescape_

- `kubescape` **C-0212** · MEDIUM · CIS cis-aks-t1.2.0:4.7.3; cis-aks-t1.8.0:4.7.3; cis-eks-t1.7.0:4.5.2; cis-eks-t1.8.0:4.5.2; cis-gke-v1.9.0:4.6.4; cis-v1.10.0:5.7.4; cis-v1.12.0:5.6.4 — The default namespace should not be used
  - _What:_ Kubernetes provides a default namespace, where objects are placed if no namespace is specified for them. Placing objects in this namespace makes application of RBAC and other controls more difficult.
  - _Fix:_ Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0212-thedefaultnamespaceshouldnotbeused.json)
- `checkov` **CKV_K8S_21** · CIS cis-1.5:5.7.4 — The default namespace should not be used
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DefaultNamespace.py)

### Deprecated APIs / versions  
_2 rules · tools: kube-linter, kubescape_

- `kubescape` **C-0294** · LOW — Deprecated serviceAccount field
  - _What:_ The deprecated `serviceAccount` workload field should not be used. Use `serviceAccountName` instead.
  - _Fix:_ Replace the deprecated `serviceAccount` field with `serviceAccountName` using the same service account value.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0294-deprecatedserviceaccountfield.json)
- `kube-linter` **deprecated-service-account-field** — Deprecated service account field
  - _What:_ Indicates when deployments use the deprecated serviceAccount field.
  - _Fix:_ Use the serviceAccountName field instead. If you must specify serviceAccount, ensure values for serviceAccount and serviceAccountName match.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/deprecated-service-account.yaml)

### File permissions / ownership  
_19 rules · tools: checkov, kube-bench, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0265** · HIGH · CIS cis-gke-v1.9.0:4.1.10 — system:authenticated user has elevated roles
  - _What:_ Granting permissions to the system:authenticated group is generally not recommended and can introduce security risks. This control ensures that system:authenticated users do not have cluster risking permissions.
  - _Fix:_ Review and modify your cluster's RBAC configuration to ensure that system:authenticated will have minimal permissions.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0265-authenticateduserhasrbac.json)
- `polaris` **clusterrolebindingClusterAdmin** · HIGH — The ClusterRoleBinding references the default cluster-admin ClusterRole or one with wildcard permissions
  - _What:_ Pass: The ClusterRoleBinding does not reference the default cluster-admin ClusterRole or one with wildcard permissions | Fail: The ClusterRoleBinding references the default cluster-admin ClusterRole or one with wildcard permissions
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/clusterrolebindingClusterAdmin.yaml)
- `polaris` **rolebindingClusterAdminClusterRole** · HIGH — The RoleBinding references the default cluster-admin ClusterRole or one with wildcard permissions
  - _What:_ Pass: The RoleBinding does not reference the default cluster-admin ClusterRole or one with wildcard permissions | Fail: The RoleBinding references the default cluster-admin ClusterRole or one with wildcard permissions
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/rolebindingClusterAdminClusterRole.yaml)
- `polaris` **rolebindingClusterAdminRole** · HIGH — The RoleBinding references a Role with wildcard permissions
  - _What:_ Pass: The RoleBinding does not reference a Role with wildcard permissions | Fail: The RoleBinding references a Role with wildcard permissions
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/rolebindingClusterAdminRole.yaml)
- `prowler` **rbac_minimize_node_proxy_subresource_access** · HIGH — User or group has no get, list, or watch permissions on the nodes/proxy sub-resource
  - _What:_ **RBAC permissions** to the `nodes/proxy` subresource are analyzed. Any user or group granted `get`, `list`, or `watch` via cluster-wide bindings is reported.
  - _Fix:_ Apply **least privilege**: avoid granting any verbs on `nodes/proxy` to users or groups. If access is unavoidable, limit it to trusted admins, scope narrowly, make it time-bound, and enforce **separation of duties**. Prefer namespace roles over cluster-wide bindings and review RBAC regularly as …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_node_proxy_subresource_access/rbac_minimize_node_proxy_subresource_access.metadata.json)
- `prowler` **rbac_minimize_pod_creation_access** · HIGH — Role or ClusterRole does not grant create permission on pods
  - _What:_ **Kubernetes RBAC** Roles and ClusterRoles that grant the `create` verb on `pods` are identified. Rules are examined to find permissions allowing pod creation at namespace or cluster scope.
  - _Fix:_ Apply **least privilege**: limit `pods` `create` to narrowly scoped service accounts and namespaces. Use **separation of duties** and avoid wildcards. Enforce controls with **Pod Security Admission** and policy engines (OPA/Kyverno) to block risky specs. Review RBAC regularly and remove unused …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_pod_creation_access/rbac_minimize_pod_creation_access.metadata.json)
- `prowler` **rbac_minimize_pv_creation_access** · HIGH — User or group does not have permission to create PersistentVolumes
  - _What:_ **Kubernetes RBAC** mapping of **users or groups** with the `create` verb on `persistentvolumes` through ClusterRoleBindings. Shows which principals can provision PersistentVolumes cluster-wide.
  - _Fix:_ Enforce **least privilege**: permit `create` on `persistentvolumes` only for trusted storage controllers and select administrators. Adopt **dynamic provisioning**, maintain **separation of duties**, and use **defense in depth** (Pod Security and admission policies) to prevent unsafe volumes like …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_pv_creation_access/rbac_minimize_pv_creation_access.metadata.json)
- `prowler` **rbac_minimize_service_account_token_creation** · HIGH — User or group does not have permission to create service account tokens
  - _What:_ Cluster-wide RBAC identifies users or groups granted `create` on `serviceaccounts/token` via **ClusterRoles/ClusterRoleBindings**. Highlights principals allowed to mint **service account tokens** through the TokenRequest subresource.
  - _Fix:_ Enforce **least privilege**: avoid granting `create` on `serviceaccounts/token` to human users or broad groups. Restrict to trusted controllers and scope narrowly with namespaced **Role**/**RoleBinding**. Apply **separation of duties**, periodic RBAC reviews, and **defense in depth** to limit …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_service_account_token_creation/rbac_minimize_service_account_token_creation.metadata.json)
- `prowler` **rbac_minimize_webhook_config_access** · HIGH — User or group does not have create, update, or delete permissions on webhook configurations
  - _What:_ User or group RBAC assignments that grant privileges to `create`, `update`, or `delete` `validatingwebhookconfigurations` and `mutatingwebhookconfigurations` are identified. Focus is on permissions that allow modifying **admission webhook** configuration objects.
  - _Fix:_ - Enforce **least privilege**; limit webhook config `create`, `update`, `delete` to a small, trusted admin group. - Avoid wildcard resources/verbs and use **separation of duties** with change approval. - Monitor changes via **audit logging** to provide **defense in depth**. Steps: 1. Identify the …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_webhook_config_access/rbac_minimize_webhook_config_access.metadata.json)
- `kubescape` **C-0063** · MEDIUM — Portforwarding privileges
  - _What:_ Attackers with relevant RBAC permission can use “kubectl portforward” command to establish direct communication with pods from within the cluster or even remotely. Such communication will most likely bypass existing security measures in the cluster. This control determines which subjects have permissions to use this command.
  - _Fix:_ It is recommended to prohibit “kubectl portforward” command in production environments. It is also recommended not to use subjects with this permission for daily cluster operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0063-portforwardingprivileges.json)
- `kubescape` **C-0191** · MEDIUM · CIS cis-eks-t1.7.0:4.1.8; cis-eks-t1.8.0:4.1.8; cis-gke-v1.9.0:4.1.7; cis-v1.10.0:5.1.8; cis-v1.12.0:5.1.8 — Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster
  - _What:_ Cluster roles and roles with the impersonate, bind or escalate permissions should not be granted unless strictly required. Each of these permissions allow a particular subject to escalate their privileges beyond those explicitly granted by cluster administrators
  - _Fix:_ Where possible, remove the impersonate, bind and escalate rights from subjects.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0191-limituseofthebindimpersonateandescalatepermissionsinthekubernetescluster.json)
- `kubescape` **C-0272** · MEDIUM — Workload with administrative roles
  - _What:_ This control identifies workloads where the associated service accounts have roles that grant administrative-level access across the cluster. Granting a workload such expansive permissions equates to providing it cluster admin roles. This level of access can pose a significant security risk, as it allows the workload to perform any action on any resource, potentially leading to unauthorized data …
  - _Fix:_ You should apply least privilege principle. Make sure cluster admin permissions are granted only when it is absolutely necessary. Don't use service accounts with such high permissions for daily operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0272-workloadwithadministrativeroles.json)
- `kyverno` **restrict-binding-system-groups** · MEDIUM — Restrict Binding System Groups
  - _What:_ Certain system groups exist in Kubernetes which grant permissions that are used for certain system-level functions yet typically never appropriate for other users. This policy prevents creating bindings to some of these groups including system:anonymous, system:unauthenticated, and system:masters.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-binding-system-groups/restrict-binding-system-groups.yaml)
- `trivy` **KSV-0111** · MEDIUM — User with admin access
  - _What:_ Either cluster-admin or those granted powerful permissions.
  - _Fix:_ Remove binding for clusterrole 'cluster-admin', 'admin' or 'edit'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/cluster_admin_role_is_only_used_where_required.rego)
- `checkov` **CKV2_K8S_3** — No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/ImpersonatePermissions.yaml)
- `checkov` **CKV_K8S_156** — Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RbacApproveCertificateSigningRequests.py)
- `checkov` **CKV_K8S_157** — Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RbacBindRoleBindings.py)
- `checkov` **CKV_K8S_158** — Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RbacEscalateRoles.py)
- `kube-bench` **5.1.8** · manual · CIS cis-1.11:5.1.8 — Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster
  - _What:_ [RBAC and Service Accounts] Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster
  - _Fix:_ Where possible, remove the impersonate, bind and escalate rights from subjects.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### Host ports  
_1 rules · tools: prowler_

- `prowler` **core_minimize_admission_hostport_containers** · HIGH — Pod does not use HostPorts
  - _What:_ **Kubernetes Pods** are inspected for any container declaring `ports[].hostPort`. The finding highlights workloads that bind container ports directly to the node's network stack via **HostPorts**.
  - _Fix:_ Avoid `hostPort`; publish services via **ClusterIP** with **Ingress/LoadBalancer**. Enforce admission policies to deny `hostPort` by default, permitting only a narrowly justified allowlist. Apply **least privilege** network rules, segment nodes, and monitor for unexpected host port bindings as …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_admission_hostport_containers/core_minimize_admission_hostport_containers.metadata.json)

### Image signing & verification  
_1 rules · tools: kubescape_

- `kubescape` **C-0288** · MEDIUM · manual · CIS cis-v1.10.0:3.1.3; cis-v1.12.0:3.1.3 — Bootstrap token authentication should not be used for users
  - _What:_ Kubernetes provides bootstrap tokens which are intended for use by new nodes joining the cluster These tokens are not designed for use by end-users they are specifically designed for the purpose of bootstrapping new nodes and not for general authentication
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of bootstrap tokens.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0288-bootstraptokenauthenticationshouldnotbeusedforusers.json)

### Image tag / digest pinning  
_1 rules · tools: kyverno_

- `kyverno` **restrict-pod-controller-serviceaccount-updates** · MEDIUM — Restrict Pod Controller ServiceAccount Updates
  - _What:_ ServiceAccounts which have the ability to edit/patch workloads which they created may potentially use that privilege to update to a different ServiceAccount with higher privileges. This policy, intended to be run in `enforce` mode, blocks updates to Pod controllers if those updates modify the serviceAccountName field. Updates to Pods directly for this field are not possible as it is immutable …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-pod-controller-serviceaccount-updates/restrict-pod-controller-serviceaccount-updates.yaml)

### Known CVEs / outdated versions  
_1 rules · tools: kyverno_

- `kyverno` **restrict-edit-for-endpoints** · LOW — Restrict Edit for Endpoints CVE-2021-25740
  - _What:_ Clusters not initially installed with Kubernetes 1.22 may be vulnerable to an issue defined in CVE-2021-25740 which could enable users to send network traffic to locations they would otherwise not have access to via a confused deputy attack. This was due to the system:aggregate-to-edit ClusterRole having edit permission of Endpoints. This policy, intended to run in background mode, checks if …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-edit-for-endpoints/restrict-edit-for-endpoints.yaml)

### Linux capabilities  
_1 rules · tools: kyverno_

- `kyverno` **drop-cap-net-raw** · MEDIUM — Drop CAP_NET_RAW in VPOL
  - _What:_ Capabilities permit privileged actions without giving full root access. The CAP_NET_RAW capability, enabled by default, allows processes in a container to forge packets and bind to any interface potentially leading to MitM attacks. This policy ensures that all containers explicitly drop the CAP_NET_RAW ability. Note that this policy also illustrates how to cover drop entries in any case although …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-drop-cap-net-raw/require-drop-cap-net-raw.yaml)

### Pod Security Standards / PSA / PSP  
_1 rules · tools: kubescape_

- `kubescape` **C-0068** · LOW — PSP enabled
  - _What:_ PSP enable fine-grained authorization of pod creation and it is important to enable it
  - _Fix:_ Turn Pod Security Policies on in your cluster, if you use other admission controllers to control the behavior that PSP controls, exclude this control from your scans
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0068-pspenabled.json)

### Privilege escalation  
_5 rules · tools: checkov, kyverno, trivy_

- `trivy` **KSV-0050** · CRITICAL — Do not allow privilege escalation via RBAC resources
  - _What:_ Check whether role permits escalate, bind, or impersonate on roles/rolebindings, which can lead to privilege escalation.
  - _Fix:_ Remove permissions for escalate, bind, and impersonate verbs on roles and rolebindings
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_kubernetes_rbac_resources.rego)
- `trivy` **KSV-0047** · HIGH — Do not allow privilege escalation from node proxy
  - _What:_ Check whether role permits privilege escalation from node proxy
  - _Fix:_ Create a role which does not permit privilege escalation from node proxy
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/privilege_escalation_from_node_proxy.rego)
- `kyverno` **restrict-clusterrole-nodesproxy** · MEDIUM — Restrict ClusterRole with Nodes Proxy
  - _What:_ A ClusterRole with nodes/proxy resource access allows a user to perform anything the kubelet API allows. It also allows users to bypass the API server and talk directly to the kubelet potentially circumventing audits and admission controllers. See https://blog.aquasec.com/privilege-escalation-kubernetes-rbac for more info. This policy prevents the creation of a ClusterRole if it contains the …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-clusterrole-nodesproxy/restrict-clusterrole-nodesproxy.yaml)
- `kyverno` **restrict-escalation-verbs-roles** · MEDIUM — Restrict Escalation Verbs in Roles
  - _What:_ The verbs `impersonate`, `bind`, and `escalate` may all potentially lead to privilege escalation and should be tightly controlled. This policy prevents use of these verbs in Role or ClusterRole resources.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-escalation-verbs-roles/restrict-escalation-verbs-roles.yaml)
- `checkov` **CKV2_K8S_1** — RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/RoleBindingPE.yaml)

### Privileged containers  
_3 rules · tools: trivy_

- `trivy` **KSV-0043** · CRITICAL — Do not allow impersonation of privileged groups
  - _What:_ Check whether role permits impersonating privileged groups
  - _Fix:_ Create a role which does not permit to impersonate privileged groups if not needed
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/impersonate_privileged_groups.rego)
- `trivy` **KSV-0051** · HIGH — Do not allow role binding creation and association with privileged role/clusterrole
  - _What:_ Check whether role permits creating role bindings and associating to privileged role/clusterrole
  - _Fix:_ Create a role which does not permit creation of role bindings and associating with privileged cluster role
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/allowing_create_role_binding_and_associate_privileged_clusterrole.rego)
- `trivy` **KSV-0052** · HIGH — Do not allow role to create ClusterRoleBindings and association with privileged role
  - _What:_ Check whether role permits creating role ClusterRoleBindings and association with privileged cluster role
  - _Fix:_ Create a role which does not permit to create role clusterrolebindings and associate to privileged cluster role
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/allowing_create_role_clusterrolebinding_and_associate_privileged_clusterrole.rego)

### RBAC: access to secrets  
_3 rules · tools: kube-linter, kyverno, prowler_

- `prowler` **rbac_minimize_secret_access** · HIGH — Role or ClusterRole does not grant get, list, or watch access to Kubernetes Secrets
  - _What:_ RBAC Roles and ClusterRoles granting read permissions to **Kubernetes Secrets** are identified. The evaluation looks for rules that allow `get`, `list`, or `watch` on `secrets`, either namespace-scoped or cluster-wide.
  - _Fix:_ Apply **least privilege**: avoid granting `get`, `list`, or `watch` on `secrets` except to narrowly scoped subjects. Constrain by namespace and `resourceNames` where feasible, use dedicated service accounts, avoid wildcards, and enforce **separation of duties** with policy and reviews. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_secret_access/rbac_minimize_secret_access.metadata.json)
- `kyverno` **restrict-secret-role-verbs** · MEDIUM — Restrict Secret Verbs in Roles
  - _What:_ The verbs `get`, `list`, and `watch` in a Role or ClusterRole, when paired with the Secrets resource, effectively allows Secrets to be read which may expose sensitive information. This policy prevents a Role or ClusterRole from using these verbs in tandem with Secret resources. In order to fully implement this control, it is recommended to pair this policy with another which also prevents use of …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-secret-role-verbs/restrict-secret-role-verbs.yaml)
- `kube-linter` **access-to-secrets** · CIS cis:5.1.2 — Access to secrets
  - _What:_ Indicates when a subject (Group/User/ServiceAccount) has access to Secrets. CIS Benchmark 5.1.2: Access to secrets should be restricted to the smallest possible group of users to reduce the risk of privilege escalation.
  - _Fix:_ Where possible, remove get, list and watch access to secret objects in the cluster.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/access-to-secrets.yaml)

### RBAC: cluster-admin  
_7 rules · tools: kube-bench, kube-linter, kubescape, kyverno, prowler_

- `prowler` **rbac_cluster_admin_usage** · CRITICAL — Cluster role binding does not grant the cluster-admin role
  - _What:_ RBAC ClusterRoleBindings that bind to the `cluster-admin` ClusterRole are identified, showing where subjects receive super-user permissions across all namespaces.
  - _Fix:_ Apply **least privilege**: replace `cluster-admin` with narrowly scoped Roles/ClusterRoles and bind per namespace. Reserve super-user access for break-glass, time-bound with approval and audit. Enforce **separation of duties**, review RBAC regularly, and monitor role/binding changes for **defense …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_cluster_admin_usage/rbac_cluster_admin_usage.metadata.json)
- `kubescape` **C-0185** · HIGH · CIS cis-aks-t1.2.0:4.1.1; cis-aks-t1.8.0:4.1.1; cis-eks-t1.7.0:4.1.1; cis-eks-t1.8.0:4.1.1; cis-gke-v1.9.0:4.1.1; cis-v1.10.0:5.1.1; cis-v1.12.0:5.1.1 — Ensure that the cluster-admin role is only used where required
  - _What:_ The RBAC role `cluster-admin` provides wide-ranging powers over the environment and should be used only where and when needed.
  - _Fix:_ Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a role with fewer privileges. Where possible, first bind users to a lower privileged role and then remove the clusterrolebinding to the cluster-admin role : ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0185-ensurethattheclusteradminroleisonlyusedwhererequired.json)
- `kyverno` **restrict-binding-clusteradmin** · MEDIUM — Restrict Binding to Cluster-Admin
  - _What:_ The cluster-admin ClusterRole allows any action to be performed on any resource in the cluster and its granting should be heavily restricted. This policy prevents binding to the cluster-admin ClusterRole in RoleBinding or ClusterRoleBinding resources.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-binding-clusteradmin/restrict-binding-clusteradmin.yaml)
- `kube-bench` **5.1.1** · manual · CIS cis-1.11:5.1.1 — Ensure that the cluster-admin role is only used where required
  - _What:_ [RBAC and Service Accounts] Ensure that the cluster-admin role is only used where required
  - _Fix:_ Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a role with fewer privileges. Where possible, first bind users to a lower privileged role and then remove the clusterrolebinding to the cluster-admin role : kubectl …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **cluster-admin-role-binding** · CIS cis:5.1.1 — Cluster admin role binding
  - _What:_ CIS Benchmark 5.1.1 Ensure that the cluster-admin role is only used where required
  - _Fix:_ Create and assign a separate role that has access to specific resources/actions needed for the service account.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/cluster-admin-role-binding.yaml)
- `kyverno` **block-cluster-admin-from-ns** — Block cluster-admin from modifying any object in a Namespace
  - _What:_ In some cases, it may be desirable to block operations of certain privileged users (i.e. cluster-admins) in a specific namespace. In this policy, Kyverno will look for all user operations (CREATE, UPDATE, DELETE), on every object kind, in the testnamespace namespace, and for the ClusterRole cluster-admin. The user testuser is also mentioned so it won't include all the cluster-admins in the …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-cluster-admin-from-ns/block-cluster-admin-from-ns.yaml)
- `kyverno` **block-updates-deletes** — Block Updates and Deletes
  - _What:_ Kubernetes RBAC allows for controls on kinds of resources or those with specific names. But it does not have the type of granularity often required in more complex environments. This policy restricts updates and deletes to any Service resource that contains the label `protected=true` unless by a cluster-admin.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-updates-deletes/block-updates-deletes.yaml)

### RBAC: create pods / workloads  
_4 rules · tools: kube-bench, kube-linter, kubescape, kyverno_

- `kubescape` **C-0307** · MEDIUM — Non-existent service account
  - _What:_ Pods referencing a missing ServiceAccount are rejected during admission before scheduling. Higher-level workload objects can be accepted, but their Pod creation then fails. This control detects such misconfigurations before they cause runtime errors.
  - _Fix:_ Create the referenced ServiceAccount in the workload namespace, update serviceAccountName to an existing ServiceAccount, or remove the explicit serviceAccountName if the workload should use the default service account.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0307-nonexistentserviceaccount.json)
- `kube-bench` **5.1.4** · manual · CIS cis-1.11:5.1.4 — Minimize access to create pods
  - _What:_ [RBAC and Service Accounts] Minimize access to create pods
  - _Fix:_ Where possible, remove create access to pod objects in the cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **access-to-create-pods** · CIS cis:5.1.4 — Access to create pods
  - _What:_ Indicates when a subject (Group/User/ServiceAccount) has create access to Pods. CIS Benchmark 5.1.4: The ability to create pods in a cluster opens up possibilities for privilege escalation and should be restricted, where possible.
  - _Fix:_ Where possible, remove create access to pod objects in the cluster.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/access-to-create-pods.yaml)
- `kyverno` **check-sa** — Check ServiceAccount
  - _What:_ ServiceAccounts with privileges to create Pods may be able to do so and name a ServiceAccount other than the one used to create it. This policy checks the Pod, if created by a ServiceAccount, and ensures the `serviceAccountName` field matches the actual ServiceAccount.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-serviceaccount/check-serviceaccount.yaml)

### RBAC: exec / attach  
_7 rules · tools: polaris, trivy_

- `polaris` **clusterrolePodExecAttach** · HIGH — The ClusterRole allows Pods/exec or pods/attach
  - _What:_ Pass: The ClusterRole does not allow pods/exec or pods/attach | Fail: The ClusterRole allows Pods/exec or pods/attach
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/clusterrolePodExecAttach.yaml)
- `polaris` **clusterrolebindingPodExecAttach** · HIGH — The ClusterRoleBinding references a ClusterRole that allows Pods/exec, allows pods/attach, or that does not exist
  - _What:_ Pass: The ClusterRoleBinding does not reference a ClusterRole allowing pods/exec or pods/attach | Fail: The ClusterRoleBinding references a ClusterRole that allows Pods/exec, allows pods/attach, or that does not exist
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/clusterrolebindingPodExecAttach.yaml)
- `polaris` **rolePodExecAttach** · HIGH — The Role allows Pods/exec or pods/attach
  - _What:_ Pass: The Role does not allow pods/exec or pods/attach | Fail: The Role allows Pods/exec or pods/attach
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/rolePodExecAttach.yaml)
- `polaris` **rolebindingClusterRolePodExecAttach** · HIGH — The RoleBinding references a ClusterRole that allows Pods/exec, allows pods/attach, or that does not exist
  - _What:_ Pass: The RoleBinding does not reference a ClusterRole allowing pods/exec or pods/attach | Fail: The RoleBinding references a ClusterRole that allows Pods/exec, allows pods/attach, or that does not exist
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/rolebindingClusterRolePodExecAttach.yaml)
- `polaris` **rolebindingRolePodExecAttach** · HIGH — The RoleBinding references a Role that allows Pods/exec, allows pods/attach, or that does not exist
  - _What:_ Pass: The RoleBinding does not reference a Role allowing Pod exec or attach | Fail: The RoleBinding references a Role that allows Pods/exec, allows pods/attach, or that does not exist
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/rolebindingRolePodExecAttach.yaml)
- `trivy` **KSV-0053** · HIGH — Exec into Pods
  - _What:_ The ability to exec into a container with privileged access to the host or with an attached SA with higher RBAC permissions is a common escalation path to cluster-admin.
  - _Fix:_ Remove write permission verbs for resource 'pods/exec'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/get_shell_on_pod.rego)
- `trivy` **KSV-0054** · HIGH — Do not allow attaching to shell on pods
  - _What:_ Check whether role permits attaching to shell on pods
  - _Fix:_ Create a role which does not permit attaching to shell on pods
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/attaching_pod_view_logs_realtime.rego)

### RBAC: impersonate / bind / escalate  
_4 rules · tools: kubescape, prowler_

- `prowler` **scheduler_bind_address** · HIGH — Scheduler pod has --bind-address set to 127.0.0.1
  - _What:_ **Kubernetes scheduler** is configured with `--bind-address=127.0.0.1` so its health and metrics endpoints listen only on localhost. The evaluation inspects scheduler pod commands for this bind address.
  - _Fix:_ Bind the scheduler to localhost with `--bind-address=127.0.0.1` and disable insecure serving (`--port=0`). Use the secure port with TLS, restrict access via private networks or network policies, and limit metrics exposure. Apply **least privilege** and **defense in depth**, and monitor access. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/scheduler/scheduler_bind_address/scheduler_bind_address.metadata.json)
- `kubescape` **C-0062** · MEDIUM — Sudo in container entrypoint
  - _What:_ Adding sudo to a container entry point command may escalate process privileges and allow access to forbidden resources. This control checks all the entry point commands in all containers in the pod to find those that have sudo command.
  - _Fix:_ Remove sudo from the command line and use Kubernetes native root and capabilities controls to provide necessary privileges where they are required.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0062-sudoincontainerentrypoint.json)
- `kubescape` **C-0065** · MEDIUM — No impersonation
  - _What:_ Impersonation is an explicit RBAC permission to use other roles rather than the one assigned to a user, group or service account. This is sometimes needed for testing purposes. However, it is highly recommended not to use this capability in the production environments for daily operations. This control identifies all subjects whose roles include impersonate verb.
  - _Fix:_ Either remove the impersonate verb from the role where it was found or make sure that this role is not bound to users, groups or service accounts used for ongoing cluster operations. If necessary, bind this role to a subject only for specific needs for limited time period.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0065-noimpersonation.json)
- `kubescape` **C-0152** · MEDIUM · CIS cis-v1.10.0:1.4.2; cis-v1.12.0:1.4.2 — Ensure that the Scheduler --bind-address argument is set to 127.0.0.1
  - _What:_ Do not bind the scheduler service to non-loopback insecure addresses.
  - _Fix:_ Edit the Scheduler pod specification file `/etc/kubernetes/manifests/kube-scheduler.yaml` on the Control Plane node and ensure the correct value for the `--bind-address` parameter
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0152-ensurethattheschedulerbindaddressargumentissetto127001.json)

### RBAC: system:masters / anonymous  
_6 rules · tools: gatekeeper, kube-bench, kubescape, trivy_

- `trivy` **KSV-0122** · CRITICAL — Anonymous user access binding
  - _What:_ Binding to anonymous user to any clusterrole or role is a security risk.
  - _Fix:_ Remove anonymous user binding from clusterrolebinding or rolebinding.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/anonymous_user_bind.rego)
- `trivy` **KSV-0123** · CRITICAL — system:masters group access binding
  - _What:_ Binding to system:masters group to any clusterrole or role is a security risk.
  - _Fix:_ Remove system:masters group binding from clusterrolebinding or rolebinding.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/masters_group_bind.rego)
- `kubescape` **C-0246** · HIGH · manual · CIS cis-gke-v1.9.0:4.1.6; cis-v1.10.0:5.1.7; cis-v1.12.0:5.1.7 — Avoid use of system:masters group
  - _What:_ The special group `system:masters` should not be used to grant permissions to any user or service account, except where strictly necessary (e.g. bootstrapping access prior to RBAC being fully available)
  - _Fix:_ Remove the `system:masters` group from all users in the cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0246-avoiduseofsystemmastersgroup.json)
- `kubescape` **C-0262** · HIGH · CIS cis-gke-v1.9.0:4.1.8 — Anonymous user has RoleBinding
  - _What:_ Granting permissions to the system:unauthenticated or system:anonymous user is generally not recommended and can introduce security risks. Allowing unauthenticated access to your Kubernetes cluster can lead to unauthorized access, potential data breaches, and abuse of cluster resources.
  - _Fix:_ Review and modify your cluster's RBAC configuration to ensure that only authenticated and authorized users have appropriate permissions based on their roles and responsibilities within your system.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0262-anonymousaccessisenabled.json)
- `gatekeeper` **k8sdisallowanonymous** — Disallow Anonymous Access
  - _What:_ Disallows associating ClusterRole and Role resources to the system:anonymous user and system:unauthenticated group.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/disallowanonymous/template.yaml)
- `kube-bench` **5.1.7** · manual · CIS cis-1.11:5.1.7 — Avoid use of system:masters group
  - _What:_ [RBAC and Service Accounts] Avoid use of system:masters group
  - _Fix:_ Remove the system:masters group from all users in the cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### RBAC: wildcards  
_9 rules · tools: checkov, kube-bench, kube-linter, kubescape, kyverno, prowler, trivy_

- `trivy` **KSV-0044** · CRITICAL — No wildcard verb and resource roles
  - _What:_ Check whether role permits wildcard verb on wildcard resource
  - _Fix:_ Create a role which does not permit wildcard verb on wildcard resource
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/any_any.rego)
- `trivy` **KSV-0045** · CRITICAL — No wildcard verb roles
  - _What:_ Check whether role permits wildcard verb on specific resources
  - _Fix:_ Create a role which does not permit wildcard verb on specific resources
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/any_verb.rego)
- `kubescape` **C-0187** · HIGH · CIS cis-aks-t1.2.0:4.1.3; cis-aks-t1.8.0:4.1.3; cis-eks-t1.7.0:4.1.3; cis-eks-t1.8.0:4.1.3; cis-gke-v1.9.0:4.1.3; cis-v1.10.0:5.1.3; cis-v1.12.0:5.1.3 — Minimize wildcard use in Roles and ClusterRoles
  - _What:_ Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard "\*" which matches all items. Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as …
  - _Fix:_ Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0187-minimizewildcarduseinrolesandclusterroles.json)
- `prowler` **rbac_minimize_wildcard_use_roles** · HIGH — Role or ClusterRole does not use wildcard resources or verbs
  - _What:_ **Kubernetes RBAC Roles/ClusterRoles** are evaluated for wildcard use in rule `resources` or `verbs`. The presence of `*` means all resources or all actions are granted. This finding highlights roles whose rules include such wildcards.
  - _Fix:_ Apply **least privilege**: replace `*` with explicit `resources`, `verbs`, and `resourceNames`. Split read/write duties, scope Roles to namespaces, use ClusterRoles only when needed, and bind to specific subjects. Periodically review roles to prevent privilege creep as part of **defense in …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_wildcard_use_roles/rbac_minimize_wildcard_use_roles.metadata.json)
- `kyverno` **restrict-wildcard-resources** · MEDIUM — Restrict Wildcards in Resources
  - _What:_ Wildcards ('*') in resources grants access to all of the resources referenced by the given API group and does not follow the principal of least privilege. As much as possible, avoid such open resources unless scoped to perhaps a custom API group. This policy blocks any Role or ClusterRole that contains a wildcard entry in the resources list found in any rule.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-wildcard-resources/restrict-wildcard-resources.yaml)
- `kyverno` **restrict-wildcard-verbs** · MEDIUM — Restrict Wildcard in Verbs
  - _What:_ Wildcards ('*') in verbs grants all access to the resources referenced by it and does not follow the principal of least privilege. As much as possible, avoid such open verbs unless scoped to perhaps a custom API group. This policy blocks any Role or ClusterRole that contains a wildcard entry in the verbs list found in any rule.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-wildcard-verbs/restrict-wildcard-verbs.yaml)
- `checkov` **CKV_K8S_49** · CIS cis-1.6:5.1.3 — Minimize wildcard use in Roles and ClusterRoles
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/WildcardRoles.py)
- `kube-bench` **5.1.3** · manual · CIS cis-1.11:5.1.3 — Minimize wildcard use in Roles and ClusterRoles
  - _What:_ [RBAC and Service Accounts] Minimize wildcard use in Roles and ClusterRoles
  - _Fix:_ Where possible replace any use of wildcards ["*"] in roles and clusterroles with specific objects or actions. Condition: role_is_compliant is false if ["*"] is found in rules. Condition: clusterrole_is_compliant is false if ["*"] is found in rules.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **wildcard-in-rules** · CIS cis:5.1.3 — Wildcard in rules
  - _What:_ Indicate when a wildcard is used in Role or ClusterRole rules. CIS Benchmark 5.1.3 Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as CRDs or in later versions of the product.
  - _Fix:_ Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/wildcard-use-in-rules.yaml)

### Read-only root filesystem  
_1 rules · tools: kyverno_

- `kyverno` **require-ro-rootfs** · MEDIUM — Require Read-Only Root Filesystem
  - _What:_ Containers must have a read-only root filesystem to prevent unauthorized modifications. This policy ensures readOnlyRootFilesystem is set to true in the securityContext of all containers.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-ro-rootfs/require-ro-rootfs.yaml)

### Run as non-root user  
_1 rules · tools: kubescape_

- `kubescape` **C-0013** · MEDIUM — Non-root containers
  - _What:_ Potential attackers may gain access to a container and leverage its existing privileges to conduct an attack. Therefore, it is not recommended to deploy containers with root privileges unless it is absolutely necessary. This control identifies all the pods running as root or can escalate to root.
  - _Fix:_ If your application does not need root privileges, make sure to define runAsNonRoot as true or explicitly set the runAsUser using ID 1000 or higher under the PodSecurityContext or container securityContext. In addition, set an explicit value for runAsGroup using ID 1000 or higher.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0013-nonrootcontainers.json)

### SELinux  
_1 rules · tools: kyverno_

- `kyverno` **disallow-selinux** · MEDIUM — Disallow SELinux
  - _What:_ SELinux options can be used to escalate privileges and should not be allowed. This policy ensures that the `seLinuxOptions` field is undefined.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-selinux/disallow-selinux.yaml)

### ServiceAccount token automount  
_8 rules · tools: checkov, gatekeeper, kube-bench, kubescape, polaris_

- `kubescape` **C-0261** · HIGH — ServiceAccount token mounted
  - _What:_ Potential attacker may gain access to a workload and steal its ServiceAccount token. Therefore, it is recommended to disable automatic mapping of the ServiceAccount tokens in ServiceAccount configuration. Enable it only for workloads that need to use them and ensure that this ServiceAccount is not bound to an unnecessary ClusterRoleBinding or RoleBinding.
  - _Fix:_ Disable automatic mounting of service account tokens to pods at the workload level, by specifying automountServiceAccountToken: false. Enable it only for workloads that need to use them and ensure that this ServiceAccount doesn't have unnecessary permissions
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0261-satokenmounted.json)
- `kubescape` **C-0309** · HIGH — Agent Sandbox service account token isolation
  - _What:_ Ensure Agent Sandbox workloads do not receive Kubernetes service account tokens unless an operator deliberately accepts that trust-boundary exception.
  - _Fix:_ Set spec.podTemplate.spec.automountServiceAccountToken to false on direct Sandbox resources. SandboxTemplate resources may omit the field because the template controller securely defaults it to false, but must never set it to true.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0309-agentsandboxserviceaccounttokenisolation.json)
- `kubescape` **C-0290** · MEDIUM · CIS cis-v1.12.0:1.2.30 — Ensure that the --service-account-extend-token-expiration parameter is set to false
  - _What:_ By default Kubernetes extends service account token lifetimes to one year. This should be set to false for security.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the below parameter. ``` --service-account-extend-token-expiration=false ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0290-ensurethattheserviceaccountextendtokenexpirationparameterissettofalse.json)
- `polaris` **automountServiceAccountToken** · MEDIUM — The ServiceAccount will be automounted
  - _What:_ Pass: The ServiceAccount will not be automounted | Fail: The ServiceAccount will be automounted
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/automountServiceAccountToken.yaml)
- `checkov` **CKV_K8S_38** · CIS cis-1.5:5.1.6 — Ensure that Service Account Tokens are only mounted where necessary
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ServiceAccountTokens.py)
- `gatekeeper` **k8spspautomountserviceaccounttokenpod** — Automount Service Account Token for Pod
  - _What:_ Controls the ability of any Pod to enable automountServiceAccountToken.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/automount-serviceaccount-token/template.yaml)
- `kube-bench` **5.1.13** · manual · CIS cis-1.11:5.1.13 — Minimize access to the service account token creation
  - _What:_ [RBAC and Service Accounts] Minimize access to the service account token creation
  - _Fix:_ Where possible, remove access to the token sub-resource of serviceaccount objects.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.1.6** · manual · CIS cis-1.11:5.1.6 — Ensure that Service Account Tokens are only mounted where necessary
  - _What:_ [RBAC and Service Accounts] Ensure that Service Account Tokens are only mounted where necessary
  - _Fix:_ Modify the definition of ServiceAccounts and Pods which do not need to mount service account tokens to disable it, with `automountServiceAccountToken: false`. If both the ServiceAccount and the Pod's .spec specify a value for automountServiceAccountToken, the Pod spec takes precedence. Condition: …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### TLS / certificates / ciphers  
_2 rules · tools: kube-bench, prowler_

- `prowler` **rbac_minimize_csr_approval_access** · HIGH — User or group lacks update and patch access to the certificatesigningrequests/approval sub-resource
  - _What:_ **RBAC assignments** that grant `update` or `patch` on the `certificatesigningrequests/approval` subresource to **users or groups** via cluster-wide roles and bindings. This highlights principals allowed to approve CSRs based on permissions defined in referenced ClusterRoles.
  - _Fix:_ Apply **least privilege**: allow CSR approval only to a small, trusted approver role. - Enforce **separation of duties** between CSR creation and approval - Prefer automated approver controllers over manual grants - Regularly review RBAC and remove broad ClusterRoleBindings - Use **defense in …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/rbac/rbac_minimize_csr_approval_access/rbac_minimize_csr_approval_access.metadata.json)
- `kube-bench` **5.1.11** · manual · CIS cis-1.11:5.1.11 — Minimize access to the approval sub-resource of certificatesigningrequests objects
  - _What:_ [RBAC and Service Accounts] Minimize access to the approval sub-resource of certificatesigningrequests objects
  - _Fix:_ Where possible, remove access to the approval sub-resource of certificatesigningrequests objects.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### hostPath volumes  
_1 rules · tools: kyverno_

- `kyverno` **disallow-host-path** · MEDIUM — Disallow hostPath
  - _What:_ HostPath volumes let Pods use host directories and volumes in containers. Using host resources can be used to access shared data or escalate privileges and should not be allowed. This policy ensures no hostPath volumes are in use.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-host-path/disallow-host-path.yaml)

### Other  
_11 rules · tools: checkov, kube-bench, kube-linter, kubescape, trivy_

- `trivy` **KSV-01011** · CRITICAL — system:authenticate group access binding
  - _What:_ Binding to system:authenticate group to any clusterrole or role is a security risk.
  - _Fix:_ Remove system:authenticated group binding from clusterrolebinding or rolebinding.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/authenticate_group_bind.rego)
- `kubescape` **C-0088** · HIGH · CIS cis-aks-t1.2.0:5.5.1; cis-aks-t1.8.0:5.5.1; cis-gke-v1.9.0:5.8.3 — RBAC enabled
  - _What:_ RBAC is the most advanced and well accepted mode of authorizing users of the Kubernetes API
  - _Fix:_ Enable RBAC either in the API server configuration or with the Kubernetes provider API
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0088-rbacenabled.json)
- `kubescape` **C-0227** · HIGH · CIS cis-eks-t1.7.0:5.4.1; cis-eks-t1.8.0:5.4.1; cis-gke-v1.9.0:5.6.3 — Restrict Access to the Control Plane Endpoint
  - _What:_ Enable Endpoint Private Access to restrict access to the cluster's control plane to only an allowlist of authorized IPs.
  - _Fix:_ By enabling private endpoint access to the Kubernetes API server, all communication between your nodes and the API server stays within your VPC. You can also limit the IP addresses that can access your API server from the internet, or completely disable internet access to the API server. With this …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0227-restrictaccesstothecontrolplaneendpoint.json)
- `kubescape` **C-0274** · HIGH — Verify Authenticated Service
  - _What:_ Verifies if the service is authenticated
  - _Fix:_ Configure the service to require authentication.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0274-unauthenticatedservice.json)
- `kubescape` **C-0223** · MEDIUM · CIS cis-eks-t1.7.0:5.1.3; cis-eks-t1.8.0:5.1.3; cis-gke-v1.9.0:5.1.3 — Minimize cluster access to read-only for Amazon ECR
  - _What:_ Configure the Cluster Service Account with Storage Object Viewer Role to only allow read-only access to Amazon ECR.
  - _Fix:_ You can use your Amazon ECR images with Amazon EKS, but you need to satisfy the following prerequisites. The Amazon EKS worker node IAM role (NodeInstanceRole) that you use with your worker nodes must possess the following IAM policy permissions for Amazon ECR. ``` { "Version": "2012-10-17", …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0223-minimizeclusteraccesstoreadonlyforamazonecr.json)
- `trivy` **KSV-0055** · LOW — Do not allow users in a rolebinding to add other users to their rolebindings
  - _What:_ Check whether role permits allowing users in a rolebinding to add other users to their rolebindings
  - _Fix:_ Create a role which does not permit allowing users in a rolebinding to add other users to their rolebindings if not needed
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/allowing_users_rolebinding_add_other_users_rolebindings.rego)
- `checkov` **CKV_K8S_155** — Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RbacControlWebhooks.py)
- `kube-bench` **5.1.10** · manual · CIS cis-1.11:5.1.10 — Minimize access to the proxy sub-resource of nodes
  - _What:_ [RBAC and Service Accounts] Minimize access to the proxy sub-resource of nodes
  - _Fix:_ Where possible, remove access to the proxy sub-resource of node objects.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.1.12** · manual · CIS cis-1.11:5.1.12 — Minimize access to webhook configuration objects
  - _What:_ [RBAC and Service Accounts] Minimize access to webhook configuration objects
  - _Fix:_ Where possible, remove access to the validatingwebhookconfigurations or mutatingwebhookconfigurations objects
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.1.9** · manual · CIS cis-1.11:5.1.9 — Minimize access to create persistent volumes
  - _What:_ [RBAC and Service Accounts] Minimize access to create persistent volumes
  - _Fix:_ Where possible, remove create access to PersistentVolume objects in the cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **non-existent-service-account** — Non existent service account
  - _What:_ Indicates when pods reference a service account that is not found.
  - _Fix:_ Create the missing service account, or refer to an existing service account.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/non-existent-service-account.yaml)


## Resources, availability & reliability

### Allowed / trusted registries  
_1 rules · tools: kyverno_

- `kyverno` **allowed-podpriorities** — Allowed Pod Priorities in cel expressions
  - _What:_ A Pod PriorityClass is used to provide a guarantee on the scheduling of a Pod relative to others. In certain cases where not all users in a cluster are trusted, a malicious user could create Pods at the highest possible priorities, causing other Pods to be evicted/not get scheduled. This policy checks the defined `priorityClassName` in a Pod spec to a dictionary of allowable PriorityClasses for …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/allowed-pod-priorities/allowed-pod-priorities.yaml)

### CPU/memory limits & requests  
_34 rules · tools: checkov, gatekeeper, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0004** · HIGH — Resources memory limit and request
  - _What:_ This control identifies all Pods for which the memory limit is not set.
  - _Fix:_ Set the memory limit or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0004-resourcesmemorylimitandrequest.json)
- `kubescape` **C-0009** · HIGH — Resource limits
  - _What:_ CPU and memory resources should have a limit set for every container or a namespace to prevent resource exhaustion. This control identifies all the pods without resource limit definitions by checking their yaml definition file as well as their namespace LimitRange objects. It is also recommended to use ResourceQuota object to restrict overall namespace resources, but this is not verified by this …
  - _Fix:_ Define LimitRange and Resource Limits in the namespace or in the deployment/pod manifests.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0009-resourcelimits.json)
- `kubescape` **C-0050** · HIGH — Resources CPU limit and request
  - _What:_ This control identifies all Pods for which the CPU limit is not set.
  - _Fix:_ Set the CPU limit or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0050-resourcescpulimitandrequest.json)
- `kubescape` **C-0270** · HIGH — Ensure CPU limits are set
  - _What:_ This control identifies all Pods for which the CPU limits are not set.
  - _Fix:_ Set the CPU limits or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0270-ensurecpulimitsareset.json)
- `kubescape` **C-0271** · HIGH — Ensure memory limits are set
  - _What:_ This control identifies all Pods for which the memory limits are not set.
  - _Fix:_ Set the memory limits or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0271-ensurememorylimitsareset.json)
- `kubescape` **C-0317** · HIGH — Agent Substrate Worker Pod resource ceilings
  - _What:_ WorkerPool resource limits bound each worker Pod. They are not per-actor limits.
  - _Fix:_ Set spec.template.resources.limits.cpu and memory at or below configured cpu_limit_max and memory_limit_max values.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0317-worker-pod-resource-ceilings.json)
- `kyverno` **memory-requests-equal-limits** · MEDIUM — Memory Requests Equal Limits
  - _What:_ Pods which have memory limits equal to requests could be given a QoS class of Guaranteed if they also set CPU limits equal to requests. Guaranteed is the highest schedulable class. This policy checks that all containers in a given Pod have memory requests equal to limits.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/memory-requests-equal-limits/memory-requests-equal-limits.yaml)
- `kyverno` **require-requests-limits** · MEDIUM — Require Requests and Limits
  - _What:_ This policy validates that all containers have CPU and memory resource requests and memory limits defined.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-pod-requests-limits/require-pod-requests-limits.yaml)
- `polaris` **cpuLimitsMissing** · MEDIUM — CPU limits should be set
  - _What:_ Pass: CPU limits are set | Fail: CPU limits should be set
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/cpuLimitsMissing.yaml)
- `polaris` **cpuRequestsMissing** · MEDIUM — CPU requests should be set
  - _What:_ Pass: CPU requests are set | Fail: CPU requests should be set
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/cpuRequestsMissing.yaml)
- `polaris` **memoryLimitsMissing** · MEDIUM — Memory limits should be set
  - _What:_ Pass: Memory limits are set | Fail: Memory limits should be set
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/memoryLimitsMissing.yaml)
- `polaris` **memoryRequestsMissing** · MEDIUM — Memory requests should be set
  - _What:_ Pass: Memory requests are set | Fail: Memory requests should be set
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/memoryRequestsMissing.yaml)
- `prowler` **core_cpu_limits_set** · MEDIUM — Pod containers have CPU limits set
  - _What:_ Ensure CPU limits are set for containers to prevent noisy neighbors and resource exhaustion.
  - _Fix:_ Define CPU limits to bound a container's CPU usage and protect node stability. Steps: 1. Edit the Pod/Deployment manifest and set `resources.limits.cpu` for each container.
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_cpu_limits_set/core_cpu_limits_set.metadata.json)
- `prowler` **core_cpu_requests_set** · MEDIUM — Pod containers have CPU requests set
  - _What:_ Ensure CPU requests are set for containers to enable proper scheduling and resource guarantees.
  - _Fix:_ Define sensible CPU requests to enable efficient scheduling and fair resource allocation. Steps: 1. Edit the Pod/Deployment manifest and set `resources.requests.cpu` for each container.
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_cpu_requests_set/core_cpu_requests_set.metadata.json)
- `prowler` **core_memory_limits_set** · MEDIUM — Container memory limits are configured
  - _What:_ **Kubernetes Pods** are evaluated for containers without **memory limits** configured in `resources.limits.memory`, indicating unbounded memory consumption is permitted.
  - _Fix:_ Set **memory limits** on every container to prevent unbounded consumption and protect node stability. - Start with observed usage plus headroom; tune with **VPA** recommendations - Combine with **LimitRanges** and **ResourceQuotas** at the namespace level for **defense in depth** - Monitor memory …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_memory_limits_set/core_memory_limits_set.metadata.json)
- `prowler` **core_memory_requests_set** · MEDIUM — Container memory requests are configured
  - _What:_ **Kubernetes Pods** are evaluated for containers without **memory requests** configured in `resources.requests.memory`, indicating the scheduler cannot guarantee memory allocation.
  - _Fix:_ Set **memory requests** on every container so the scheduler can guarantee memory allocation and place pods effectively. - Base requests on observed steady-state usage; use **VPA** for data-driven sizing - Enforce minimum requests via **LimitRanges** at the namespace level - Combine with …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_memory_requests_set/core_memory_requests_set.metadata.json)
- `kubescape` **C-0268** · LOW — Ensure CPU requests are set
  - _What:_ This control identifies all Pods for which the CPU requests are not set.
  - _Fix:_ Set the CPU requests or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0268-ensurecpurequestsareset.json)
- `kubescape` **C-0269** · LOW — Ensure memory requests are set
  - _What:_ This control identifies all Pods for which the memory requests are not set.
  - _Fix:_ Set the memory requests or use exception mechanism to avoid unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0269-ensurememoryrequestsareset.json)
- `trivy` **KSV-0011** · LOW — CPU not limited
  - _What:_ Enforcing CPU limits prevents DoS via resource exhaustion.
  - _Fix:_ Set a limit value under 'containers[].resources.limits.cpu'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/CPU_not_limited.rego)
- `trivy` **KSV-0015** · LOW — CPU requests not specified
  - _What:_ When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.
  - _Fix:_ Set 'containers[].resources.requests.cpu'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/CPU_requests_not_specified.rego)
- `trivy` **KSV-0016** · LOW — Memory requests not specified
  - _What:_ When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.
  - _Fix:_ Set 'containers[].resources.requests.memory'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/memory_requests_not_specified.rego)
- `trivy` **KSV-0018** · LOW — Memory not limited
  - _What:_ Enforcing memory limits prevents DoS via resource exhaustion.
  - _Fix:_ Set a limit value under 'containers[].resources.limits.memory'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/memory_not_limited.rego)
- `trivy` **KSV-0039** · LOW — limit range usage
  - _What:_ Ensure that a LimitRange policy is configured to limit resource usage for namespaces or nodes
  - _Fix:_ Create a LimitRange policy with default requests and limits for each container
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/use_limit_range.rego)
- `trivy` **KSV-0040** · LOW — resource quota usage
  - _What:_ Ensure that a ResourceQuota policy is configured to limit aggregate resource usage within a namespace
  - _Fix:_ Create a ResourceQuota policy with memory and CPU quotas for each namespace
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/use_resource_quota.rego)
- `checkov` **CKV_K8S_10** — CPU requests should be set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/CPURequests.py)
- `checkov` **CKV_K8S_11** — CPU limits should be set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/CPULimits.py)
- `checkov` **CKV_K8S_12** — Memory requests should be set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/MemoryRequests.py)
- `checkov` **CKV_K8S_13** — Memory limits should be set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/MemoryLimits.py)
- `gatekeeper` **k8scontainerlimits** — Container Limits
  - _What:_ Requires containers to have memory and CPU limits set and constrains limits to be within the specified maximum values. https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/containerlimits/template.yaml)
- `gatekeeper` **k8scontainerratios** — Container Ratios
  - _What:_ Sets a maximum ratio for container resource limits to requests. https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/containerresourceratios/template.yaml)
- `gatekeeper` **k8scontainerrequests** — Container Requests
  - _What:_ Requires containers to have memory and CPU requests set and constrains requests to be within the specified maximum values. https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/containerrequests/template.yaml)
- `kube-linter` **unset-cpu-requirements** — Unset cpu requirements
  - _What:_ Indicates when containers do not have CPU requests and limits set.
  - _Fix:_ Set CPU requests for your container based on its requirements. Refer to https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/unset-cpu-requirements.yaml)
- `kube-linter` **unset-memory-requirements** — Unset memory requirements
  - _What:_ Indicates when containers do not have memory requests and limits set.
  - _Fix:_ Set memory limits for your container based on its requirements. Refer to https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/unset-memory-requirements.yaml)
- `kyverno` **forbid-cpu-limits** — Forbid CPU Limits
  - _What:_ Setting of CPU limits is a debatable poor practice as it can result, when defined, in potentially starving applications of much-needed CPU cycles even when they are available. Ensuring that CPU limits are not set may ensure apps run more effectively. This policy forbids any container in a Pod from defining CPU limits.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/forbid-cpu-limits/forbid-cpu-limits.yaml)

### Liveness / readiness probes  
_15 rules · tools: checkov, gatekeeper, kube-linter, kubescape, kyverno, polaris, prowler_

- `kubescape` **C-0056** · MEDIUM — Configured liveness probe
  - _What:_ Liveness probe is intended to ensure that workload remains healthy during its entire execution lifecycle, or otherwise restrat the container. It is highly recommended to define liveness probe for every worker container. This control finds all the pods where the Liveness probe is not configured.
  - _Fix:_ Ensure Liveness probes are configured wherever possible.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0056-configuredlivenessprobe.json)
- `kyverno` **validate-probes** · MEDIUM — Validate Probes
  - _What:_ Liveness and readiness probes accomplish different goals, and setting both to the same is an anti-pattern and often results in app problems in the future. This policy checks that liveness and readiness probes are not equal. Keep in mind that if both the probes are not set, they are considered to be equal and hence fails the check.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/ensure-probes-different/ensure-probes-different.yaml)
- `polaris` **livenessProbeMissing** · MEDIUM — Liveness probe should be configured
  - _What:_ Pass: Liveness probe is configured | Fail: Liveness probe should be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/livenessProbeMissing.yaml)
- `polaris` **readinessProbeMissing** · MEDIUM — Readiness probe should be configured
  - _What:_ Pass: Readiness probe is configured | Fail: Readiness probe should be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/readinessProbeMissing.yaml)
- `prowler` **core_liveness_probe_configured** · MEDIUM — Pod containers have liveness probes configured
  - _What:_ Ensure each regular pod container has a liveness probe configured to detect and restart unhealthy containers.
  - _Fix:_ Add and tune liveness probes for containers to allow Kubernetes to detect and restart unhealthy containers. Steps: 1. Edit the Pod/Deployment manifest and add a `livenessProbe` to each container. 2. Tune `initialDelaySeconds`, `periodSeconds` and failure thresholds to your app.
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_liveness_probe_configured/core_liveness_probe_configured.metadata.json)
- `prowler` **core_readiness_probe_configured** · MEDIUM — Regular pod containers have readiness probes configured
  - _What:_ Ensure each regular pod container has a readiness probe configured to signal when it is ready to serve traffic.
  - _Fix:_ Add readiness probes to prevent routing traffic to unready containers. Steps: 1. Add a `readinessProbe` to the container spec in Deployments/Pods. 2. Ensure the probe accurately reflects service readiness.
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_readiness_probe_configured/core_readiness_probe_configured.metadata.json)
- `kubescape` **C-0018** · LOW — Configured readiness probe
  - _What:_ Readiness probe is intended to ensure that workload is ready to process network traffic. It is highly recommended to define readiness probe for every worker container. This control finds all the pods where the readiness probe is not configured.
  - _Fix:_ Ensure Readiness probes are configured wherever possible.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0018-configuredreadinessprobe.json)
- `checkov` **CKV_K8S_8** — Liveness Probe Should be Configured
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/LivenessProbe.py)
- `checkov` **CKV_K8S_9** — Readiness Probe Should be Configured
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ReadinessProbe.py)
- `gatekeeper` **k8srequiredprobes** — Required Probes
  - _What:_ Requires Pods to have readiness and/or liveness probes.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/requiredprobes/template.yaml)
- `kube-linter` **liveness-port** — Liveness port
  - _What:_ Indicates when containers have a liveness probe to a not exposed port.
  - _Fix:_ Check which ports you've exposed and ensure they match what you have specified in the liveness probe.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/liveness-port.yaml)
- `kube-linter` **no-liveness-probe** — No liveness probe
  - _What:_ Indicates when containers fail to specify a liveness probe.
  - _Fix:_ Specify a liveness probe in your container. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/ for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-liveness-probe.yaml)
- `kube-linter` **no-readiness-probe** — No readiness probe
  - _What:_ Indicates when containers fail to specify a readiness probe.
  - _Fix:_ Specify a readiness probe in your container. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/ for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-readiness-probe.yaml)
- `kube-linter` **readiness-port** — Readiness port
  - _What:_ Indicates when containers have a readiness probe to a not exposed port.
  - _Fix:_ Check which ports you've exposed and ensure they match what you have specified in the readiness probe.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/readiness-port.yaml)
- `kube-linter` **startup-port** — Startup port
  - _What:_ Indicates when containers have a startup probe to a not exposed port.
  - _Fix:_ Check which ports you've exposed and ensure they match what you have specified in the startup probe.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/startup-port.yaml)

### Replicas / PDB / availability  
_22 rules · tools: gatekeeper, kube-linter, kubescape, kyverno, polaris_

- `kubescape` **C-0300** · MEDIUM — Dangling HPA target
  - _What:_ A HorizontalPodAutoscaler whose scaleTargetRef points to a workload that does not exist in the same namespace silently does nothing — no scaling occurs and the failure surfaces only under load. Only built-in scalable kinds (Deployment, StatefulSet, ReplicaSet, ReplicationController) are validated; custom scalable resources are skipped.
  - _Fix:_ Create the referenced workload or correct the HPA scaleTargetRef.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0300-danglinghpatarget.json)
- `kyverno` **check-hpa-exists** · MEDIUM — Ensure HPA for Deployments
  - _What:_ This policy ensures that Deployments, ReplicaSets, StatefulSets, and DaemonSets are only allowed if they have a corresponding Horizontal Pod Autoscaler (HPA) configured in the same namespace. The policy checks for the presence of an HPA that targets the resource and denies the creation or update of the resource if no such HPA exists. This policy helps enforce scaling practices and ensures that …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-hpa-exists/check-hpa-exists.yaml)
- `kyverno` **deployment-has-multiple-replicas** · MEDIUM — Require Multiple Replicas
  - _What:_ Deployments with a single replica cannot be highly available and thus the application may suffer downtime if that one replica goes down. This policy validates that Deployments have more than one replica.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-deployments-have-multiple-replicas/require-deployments-have-multiple-replicas.yaml)
- `kyverno` **topologyspreadconstraints-policy** · MEDIUM — Spread Pods Across Nodes & Zones
  - _What:_ Deployments to a Kubernetes cluster with multiple availability zones often need to distribute those replicas to align with those zones to ensure site-level failures do not impact availability. This policy ensures topologySpreadConstraints are defined, to spread pods over nodes and zones. Deployments or Statefulsets with less than 3 replicas are skipped.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/topologyspreadconstraints-policy/topologyspreadconstraints-policy.yaml)
- `polaris` **deploymentMissingReplicas** · MEDIUM — Only one replica is scheduled
  - _What:_ Pass: Multiple replicas are scheduled | Fail: Only one replica is scheduled
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/deploymentMissingReplicas.yaml)
- `polaris` **hpaMaxAvailability** · MEDIUM — HPA maxReplicas and minReplicas should be different
  - _What:_ Pass: HPA has a valid max and min replica configuration | Fail: HPA maxReplicas and minReplicas should be different
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hpaMaxAvailability.yaml)
- `polaris` **hpaMinAvailability** · MEDIUM — HPA minReplicas should be 2 or more
  - _What:_ Pass: HPA has a valid min replica configuration | Fail: HPA minReplicas should be 2 or more
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hpaMinAvailability.yaml)
- `polaris` **missingPodDisruptionBudget** · MEDIUM — Should have a PodDisruptionBudget
  - _What:_ Pass: A PodDisruptionBudget is attached | Fail: Should have a PodDisruptionBudget
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/missingPodDisruptionBudget.yaml)
- `polaris` **pdbDisruptionsIsZero** · MEDIUM — Voluntary evictions are not possible
  - _What:_ Pass: Voluntary evictions are possible | Fail: Voluntary evictions are not possible
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/pdbDisruptionsIsZero.yaml)
- `polaris` **pdbMinAvailableGreaterThanHPAMinReplicas** · MEDIUM — PDB minAvailable is greater than HPA minReplicas
  - _What:_ Pass: PDB and HPA are correctly configured | Fail: PDB minAvailable is greater than HPA minReplicas
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/pdbMinAvailableGreaterThanHPAMinReplicas.yaml)
- `polaris` **topologySpreadConstraint** · MEDIUM — Pod should be configured with a valid topology spread constraint
  - _What:_ Pass: Pod has a valid topology spread constraint | Fail: Pod should be configured with a valid topology spread constraint
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/topologySpreadConstraint.yaml)
- `kubescape` **C-0073** · LOW — Naked pods
  - _What:_ It is not recommended to create pods without parental Deployment, ReplicaSet, StatefulSet etc.Manual creation if pods may lead to a configuration drifts and other untracked changes in the system. Such pods won't be automatically rescheduled by Kubernetes in case of a crash or infrastructure failure. This control identifies every pod that does not have corresponding parental object.
  - _Fix:_ Create necessary Deployment object for every pod making any pod a first class citizen in your IaC architecture.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0073-nakedpods.json)
- `gatekeeper` **k8shorizontalpodautoscaler** — Horizontal Pod Autoscaler
  - _What:_ Disallow the following scenarios when deploying `HorizontalPodAutoscalers` 1. Deployment of HorizontalPodAutoscalers with `.spec.minReplicas` or `.spec.maxReplicas` outside the ranges defined in the constraint 2. Deployment of HorizontalPodAutoscalers where the difference between `.spec.minReplicas` and `.spec.maxReplicas` is less than the configured `minimumReplicaSpread` 3. Deployment of …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/horizontalpodautoscaler/template.yaml)
- `gatekeeper` **k8spoddisruptionbudget** — Pod Disruption Budget
  - _What:_ Disallow the following scenarios when deploying PodDisruptionBudgets or resources that implement the replica subresource (e.g. Deployment, ReplicationController, ReplicaSet, StatefulSet): 1. Deployment of PodDisruptionBudgets with .spec.maxUnavailable == 0 2. Deployment of PodDisruptionBudgets with .spec.minAvailable == .spec.replicas of the resource with replica subresource This will prevent …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/poddisruptionbudget/template.yaml)
- `gatekeeper` **k8sreplicalimits** — Replica Limits
  - _What:_ Requires that objects with the field `spec.replicas` (Deployments, ReplicaSets, etc.) specify a number of replicas within defined ranges.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/replicalimits/template.yaml)
- `kube-linter` **hpa-minimum-three-replicas** — Hpa minimum three replicas
  - _What:_ Indicates when a HorizontalPodAutoscaler specifies less than three minReplicas
  - _Fix:_ Increase the number of replicas in the HorizontalPodAutoscaler to at least three to increase fault tolerance.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/hpa-minimum-replicas.yaml)
- `kube-linter` **minimum-three-replicas** — Minimum three replicas
  - _What:_ Indicates when a deployment uses less than three replicas
  - _Fix:_ Increase the number of replicas in the deployment to at least three to increase the fault tolerance of the deployment.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/minimum-replicas.yaml)
- `kube-linter` **no-anti-affinity** — No anti affinity
  - _What:_ Indicates when deployments with multiple replicas fail to specify inter-pod anti-affinity or topology spread constraints, to ensure that the orchestrator attempts to schedule replicas on different nodes.
  - _Fix:_ Specify anti-affinity or topology spread constraints in your pod specification to ensure that the orchestrator attempts to schedule replicas on different nodes. Using podAntiAffinity or topologySpreadConstraints, specify a labelSelector that matches pods for the deployment, and set the topologyKey …
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-anti-affinity.yaml)
- `kube-linter` **pdb-max-unavailable** — Pdb max unavailable
  - _What:_ Indicates when a PodDisruptionBudget has a maxUnavailable value that will always prevent disruptions of pods created by related deployment-like objects.
  - _Fix:_ Change the PodDisruptionBudget to have maxUnavailable set to a value greater than 0. Refer to https://kubernetes.io/docs/tasks/run-application/configure-pdb/ for more information.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/pdbs-max-unavailable.yaml)
- `kube-linter` **pdb-min-available** — Pdb min available
  - _What:_ Indicates when a PodDisruptionBudget sets a minAvailable value that will always prevent disruptions of pods created by related deployment-like objects.
  - _Fix:_ Change the PodDisruptionBudget to have minAvailable set to a number lower than the number of replicas in the related deployment-like objects. Refer to https://kubernetes.io/docs/tasks/run-application/configure-pdb/ for more information.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/pdbs-min-available.yaml)
- `kube-linter` **pdb-unhealthy-pod-eviction-policy** — Pdb unhealthy pod eviction policy
  - _What:_ Indicates when a PodDisruptionBudget does not explicitly set the unhealthyPodEvictionPolicy field.
  - _Fix:_ Set unhealthyPodEvictionPolicy to AlwaysAllow. Refer to https://kubernetes.io/docs/tasks/run-application/configure-pdb/#unhealthy-pod-eviction-policy for more information.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/pdb-unhealthy-pod-eviction-policy.yaml)
- `kyverno` **pdb-maxunavailable** — PodDisruptionBudget maxUnavailable Non-Zero
  - _What:_ A PodDisruptionBudget which sets its maxUnavailable value to zero prevents all voluntary evictions including Node drains which may impact maintenance tasks. This policy enforces that if a PodDisruptionBudget specifies the maxUnavailable field it must be greater than zero.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/pdb-maxunavailable/pdb-maxunavailable.yaml)

### TLS / certificates / ciphers  
_3 rules · tools: gatekeeper, kyverno_

- `kyverno` **inspect-csr** · MEDIUM — Inspect Certificate Signing Requests
  - _What:_ This policy inspects all CertificateSigningRequest resources and records detailed information about the requester including their identity, permissions, and the CSR content for auditing purposes.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/inspect-csr/inspect-csr.yaml)
- `gatekeeper` **k8scontainerephemeralstoragelimit** — Container ephemeral storage limit
  - _What:_ Requires containers to have an ephemeral storage limit set and constrains the limit to be within the specified maximum values. https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/ephemeralstoragelimit/template.yaml)
- `kyverno` **readwriteonce-pod** — Enforce ReadWriteOncePod
  - _What:_ Some stateful workloads with multiple replicas only allow a single Pod to write to a given volume at a time. Beginning in Kubernetes 1.22 and enabled by default in 1.27, a new setting called ReadWriteOncePod, available for CSI volumes only, allows volumes to be writable from only a single Pod. For more information see the blog …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/enforce-readwriteonce-pod/enforce-readwriteonce-pod.yaml)

### Other  
_13 rules · tools: checkov, gatekeeper, kube-linter, kyverno, polaris_

- `kyverno` **check-nvidia-gpus** · MEDIUM — Check NVIDIA GPUs
  - _What:_ Containers which request use of an NVIDIA GPU often need to be authored to consume them via a CUDA environment variable called NVIDIA_VISIBLE_DEVICES. This policy checks the containers which request a GPU to ensure they have been authored with this environment variable.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-nvidia-gpu/check-nvidia-gpu.yaml)
- `kyverno` **require-emptydir-requests-and-limits** · MEDIUM — Require Requests and Limits for emptyDir
  - _What:_ Pods which mount emptyDir volumes may be allowed to potentially overrun the medium backing the emptyDir volume. This sample ensures that any initContainers or containers mounting an emptyDir volume have ephemeral-storage requests and limits set. Policy will be skipped if the volume has already a sizeLimit set.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-emptydir-requests-limits/require-emptydir-requests-limits.yaml)
- `kyverno` **require-storageclass** · MEDIUM — Require StorageClass
  - _What:_ PersistentVolumeClaims (PVCs) and StatefulSets may optionally define a StorageClass to dynamically provision storage. In a multi-tenancy environment where StorageClasses are far more common, it is often better to require storage only be provisioned from these StorageClasses. This policy requires that PVCs and StatefulSets containing volumeClaimTemplates define the storageClassName field with …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-storageclass/require-storageclass.yaml)
- `kyverno` **restrict-node-affinity** · MEDIUM — Restrict Node Affinity
  - _What:_ Pods may use several mechanisms to prefer scheduling on a set of nodes, and nodeAffinity is one of them. nodeAffinity uses expressions to select eligible nodes for scheduling decisions and may override intended placement options by cluster administrators. This policy ensures that nodeAffinity is not used in a Pod spec.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-node-affinity/restrict-node-affinity.yaml)
- `polaris` **priorityClassNotSet** · MEDIUM — Priority class should be set
  - _What:_ Pass: Priority class has been set | Fail: Priority class should be set
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/priorityClassNotSet.yaml)
- `checkov` **CKV_K8S_159** — Limit the use of git-sync to prevent code injection
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DangerousGitSync.py)
- `gatekeeper` **k8sstorageclass** — Storage Class
  - _What:_ Requires storage classes to be specified when used. Only Gatekeeper 3.9+ and non-ephemeral containers are supported.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/storageclass/template.yaml)
- `kube-linter` **duplicate-env-var** — Duplicate env var
  - _What:_ Check that duplicate named env vars aren't passed to a deployment like.
  - _Fix:_ Confirm that your DeploymentLike doesn't have duplicate env vars names.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/duplicate-env-var.yaml)
- `kube-linter` **job-ttl-seconds-after-finished** — Job ttl seconds after finished
  - _What:_ Indicates when standalone jobs do not set ttlSecondsAfterFinished and when jobs managed by cronjob do set ttlSecondsAfterFinished.
  - _Fix:_ Set Job.spec.ttlSecondsAfterFinished. Unset CronJob.Spec.JobTemplate.Spec.ttlSecondsAfterFinished.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/job-ttl-seconds-after-finished.yaml)
- `kube-linter` **no-node-affinity** — No node affinity
  - _What:_ Alert on deployments that have no node affinity defined
  - _Fix:_ Specify node-affinity in your pod specification to ensure that the orchestrator attempts to schedule replicas on specified nodes. Refer to https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-affinity for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-node-affinity.yaml)
- `kube-linter` **no-rolling-update-strategy** — No rolling update strategy
  - _What:_ Indicates when a deployment doesn't use a rolling update strategy
  - _Fix:_ Use a rolling update strategy to avoid service disruption during an update. A rolling update strategy allows for pods to be systematicaly replaced in a controlled fashion to ensure no service disruption.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/no-rolling-update-strategy.yaml)
- `kube-linter` **priority-class-name** — Priority class name
  - _What:_ Indicates when a deployment-like object does not use a valid priority class name
  - _Fix:_ Set up the priority class name for your object to any accepted values.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/priority-class-name.yaml)
- `kyverno` **limit-containers-per-pod** — Limit Containers per Pod
  - _What:_ Pods can have many different containers which are tightly coupled. It may be desirable to limit the amount of containers that can be in a single Pod to control best practice application or so policy can be applied consistently. This policy checks all Pods to ensure they have no more than four containers.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/limit-containers-per-pod/limit-containers-per-pod.yaml)


## Secrets & encryption

### Audit logging  
_3 rules · tools: kubescape, kyverno_

- `kubescape` **C-0208** · MEDIUM · CIS cis-aks-t1.2.0:4.5.2; cis-aks-t1.8.0:4.5.2; cis-v1.10.0:5.4.2; cis-v1.12.0:5.4.2 — Consider external secret storage
  - _What:_ Consider the use of an external secrets storage and management system, instead of using Kubernetes Secrets directly, if you have more complex secret management needs. Ensure the solution requires authentication to access secrets, has auditing of access to and use of secrets, and encrypts secrets. Some solutions also make it easier to rotate secrets.
  - _Fix:_ Refer to the secrets management options offered by your cloud provider or a third-party secrets management solution.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0208-considerexternalsecretstorage.json)
- `kubescape` **C-0234** · MEDIUM · CIS cis-eks-t1.7.0:4.4.2; cis-eks-t1.8.0:4.4.2; cis-gke-v1.9.0:4.4.2 — Consider external secret storage
  - _What:_ Consider the use of an external secrets storage and management system, instead of using Kubernetes Secrets directly, if you have more complex secret management needs. Ensure the solution requires authentication to access secrets, has auditing of access to and use of secrets, and encrypts secrets. Some solutions also make it easier to rotate secrets.
  - _Fix:_ Refer to the secrets management options offered by your cloud provider or a third-party secrets management solution.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0234-considerexternalsecretstorage.json)
- `kyverno` **check-serviceaccount-secrets** · MEDIUM — Check Long-Lived Secrets in ServiceAccounts
  - _What:_ Before version 1.24, Kubernetes automatically generated Secret-based tokens for ServiceAccounts. To distinguish between automatically generated tokens and manually created ones, Kubernetes checks for a reference from the ServiceAccount's secrets field. If the Secret is referenced in the secrets field, it is considered an auto-generated legacy token. These legacy Tokens can be of security concern …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/check-serviceaccount-secrets/check-serviceaccount-secrets.yaml)

### Container runtime socket mount  
_1 rules · tools: kubescape_

- `kubescape` **C-0074** · MEDIUM — Container runtime socket mounted
  - _What:_ Mounting Container runtime socket (Unix socket) enables container to access Container runtime, retrieve sensitive information and execute commands, if Container runtime is available. This control identifies pods that attempt to mount Container runtime socket for accessing Container runtime.
  - _Fix:_ Remove container runtime socket mount request or define an exception.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0074-containersmountingdockersocket.json)

### Encryption at rest / KMS  
_1 rules · tools: checkov_

- `checkov` **CKV_K8S_104** — Ensure that encryption providers are appropriately configured
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerEncryptionProviders.py)

### File permissions / ownership  
_1 rules · tools: trivy_

- `trivy` **KSV-0041** · CRITICAL — Manage secrets
  - _What:_ Viewing secrets at the cluster-scope is akin to cluster-admin in most clusters as there are typically at least one service accounts (their token stored in a secret) bound to cluster-admin directly or a role/clusterrole that gives similar permissions.
  - _Fix:_ Manage secrets are not allowed. Remove resource 'secrets' from cluster role
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_secrets.rego)

### Image signing & verification  
_1 rules · tools: kubescape_

- `kubescape` **C-0267** · MEDIUM — Workload with cluster takeover roles
  - _What:_ Cluster takeover roles include workload creation or update and secret access. They can easily lead to super privileges in the cluster. If an attacker can exploit this workload then the attacker can take over the cluster using the RBAC privileges this workload is assigned to.
  - _Fix:_ You should apply least privilege principle. Make sure each service account has only the permissions that are absolutely necessary.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0267-workloadwithclustertakeoverroles.json)

### Image tag / digest pinning  
_1 rules · tools: kubescape_

- `kubescape` **C-0075** · LOW — Image pull policy on latest tag
  - _What:_ While usage of the latest tag is not generally recommended, in some cases this is necessary. If it is, the ImagePullPolicy must be set to Always, otherwise Kubernetes may run an older image with the same name that happens to be present in the node cache. Note that using Always will not cause additional image downloads because Kubernetes will check the image hash of the local local against the …
  - _Fix:_ Set ImagePullPolicy to Always in all pods found by this control.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0075-imagepullpolicyonlatesttag.json)

### Linux capabilities  
_1 rules · tools: kyverno_

- `kyverno` **block-kubectl-cp** — Block kubectl cp command by Pod Label
  - _What:_ The kubectl cp command is used to copy files between a local machine and a Pod's container. While this functionality is useful for transferring data, it may introduce security risks, such as unauthorized data exfiltration or modification. This policy blocks the use of the kubectl cp command on all Pods with label `block-kubectl-cp=true`, ensuring that sensitive workloads are protected from …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-kubectl-cp/block-kubectl-cp.yaml)

### Network policies  
_1 rules · tools: kyverno_

- `kyverno` **restrict-networkpolicy-empty-podselector** · MEDIUM — Restrict NetworkPolicy with Empty podSelector
  - _What:_ By default, all pods in a Kubernetes cluster are allowed to communicate with each other, and all network traffic is unencrypted. It is recommended to not use an empty podSelector in order to more closely control the necessary traffic flows. This policy requires that all NetworkPolicies other than that of `default-deny` not use an empty podSelector.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-networkpolicy-empty-podselector/restrict-networkpolicy-empty-podselector.yaml)

### NodePort / LoadBalancer / external exposure  
_1 rules · tools: kubescape_

- `kubescape` **C-0021** · MEDIUM — Exposed sensitive interfaces
  - _What:_ Exposing a sensitive interface to the internet poses a security risk. It might enable attackers to run malicious code or deploy containers in the cluster. This control checks if known components (e.g. Kubeflow, Argo Workflows, AI/ML inference servers such as Ollama, vLLM, KServe and Triton, or MLOps interfaces such as MLflow, Ray and JupyterHub) are deployed and exposed services externally.
  - _Fix:_ Consider blocking external interfaces or protect them with appropriate security tools.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0021-exposedsensitiveinterfaces.json)

### Privileged containers  
_2 rules · tools: trivy_

- `trivy` **KSV-0113** · MEDIUM — Manage namespace secrets
  - _What:_ Viewing secrets at the namespace scope can lead to escalation if another service account in that namespace has a higher privileged rolebinding or clusterrolebinding bound.
  - _Fix:_ Manage namespace secrets are not allowed. Remove resource 'secrets' from role
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_namespace_secrets.rego)
- `trivy` **KSV-0117** · MEDIUM — Prevent binding to privileged ports
  - _What:_ The ports which are lower than 1024 receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.
  - _Fix:_ Do not map the container ports to privileged host ports when starting a container.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/privileged_ports_binding.rego)

### Secrets in env vars / config  
_11 rules · tools: checkov, kube-bench, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0012** · HIGH — Applications credentials in configuration files
  - _What:_ Attackers who have access to configuration files can steal the stored secrets and use them. This control checks if ConfigMaps or pod specifications have sensitive information in their configuration.
  - _Fix:_ Use Kubernetes secrets or Key Management Systems to store credentials.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0012-applicationscredentialsinconfigurationfiles.json)
- `polaris` **sensitiveConfigmapContent** · HIGH — Potentially sensitive content is detected in the ConfigMap keys or values
  - _What:_ Pass: The ConfigMap does not contain potentially sensitive content in its keys and values | Fail: Potentially sensitive content is detected in the ConfigMap keys or values
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/sensitiveConfigmapContent.yaml)
- `polaris` **sensitiveContainerEnvVar** · HIGH — The container sets potentially sensitive environment variables
  - _What:_ Pass: The container does not set potentially sensitive environment variables | Fail: The container sets potentially sensitive environment variables
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/sensitiveContainerEnvVar.yaml)
- `prowler` **core_no_secrets_envs** · HIGH — Pod does not contain secret environment variables
  - _What:_ **Kubernetes Pods** containers define environment variables sourced from **Secrets** via `secretKeyRef` instead of mounting them as files.
  - _Fix:_ Use **Secrets as files** (read-only volumes) and load at runtime. - Apply **least privilege** RBAC to Secret access - Scope Secrets to required containers; avoid logging env - Prefer short-lived creds and regular rotation; set `immutable: true` when suitable - Layer **defense in depth** with …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_no_secrets_envs/core_no_secrets_envs.metadata.json)
- `kubescape` **C-0207** · MEDIUM · CIS cis-aks-t1.2.0:4.5.1; cis-aks-t1.8.0:4.5.1; cis-eks-t1.7.0:4.4.1; cis-eks-t1.8.0:4.4.1; cis-gke-v1.9.0:4.4.1; cis-v1.10.0:5.4.1; cis-v1.12.0:5.4.1 — Prefer using secrets as files over secrets as environment variables
  - _What:_ Kubernetes supports mounting secrets as data volumes or as environment variables. Minimize the use of environment variable secrets.
  - _Fix:_ If possible, rewrite application code to read secrets from mounted secret files, rather than from environment variables.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0207-preferusingsecretsasfilesoversecretsasenvironmentvariables.json)
- `kyverno` **limit-configmap-for-sa** · MEDIUM — Limit ConfigMap for ServiceAccount
  - _What:_ This policy demonstrates how to restrict operations on specific ConfigMaps based on the requesting ServiceAccount and other request attributes, in order to protect sensitive ConfigMaps from unauthorized changes.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/limit-configmap-for-sa/limit-configmap-for-sa.yaml)
- `trivy` **KSV-0049** · MEDIUM — Manage configmaps
  - _What:_ Some workloads leverage configmaps to store sensitive data or configuration parameters that affect runtime behavior that can be modified by an attacker or combined with another issue to potentially lead to compromise.
  - _Fix:_ Remove write permission verbs for resource 'configmaps'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_configmaps.rego)
- `checkov` **CKV_K8S_35** · CIS cis-1.5:5.4.1 — Prefer using secrets as files over secrets as environment variables
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/Secrets.py)
- `kube-bench` **5.4.1** · manual · CIS cis-1.11:5.4.1 — Prefer using Secrets as files over Secrets as environment variables
  - _What:_ [Secrets Management] Prefer using Secrets as files over Secrets as environment variables
  - _Fix:_ If possible, rewrite application code to read Secrets from mounted secret files, rather than from environment variables.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **env-var-secret** — Env var secret
  - _What:_ Indicates when objects use a secret in an environment variable.
  - _Fix:_ Do not use raw secrets in environment variables. Instead, either mount the secret as a file or use a secretKeyRef. Refer to https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/env-var-secret.yaml)
- `kube-linter` **read-secret-from-env-var** · CIS cis:5.4.1 — Read secret from env var
  - _What:_ Indicates when a deployment reads secret from environment variables. CIS Benchmark 5.4.1: "Prefer using secrets as files over secrets as environment variables. "
  - _Fix:_ If possible, rewrite application code to read secrets from mounted secret files, rather than from environment variables. Refer to https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/read-secret-from-env-var.yaml)

### ServiceAccount token automount  
_6 rules · tools: kubescape, kyverno, trivy_

- `kubescape` **C-0034** · MEDIUM — Automatic mapping of service account
  - _What:_ Potential attacker may gain access to a pod and steal its service account token. Therefore, it is recommended to disable automatic mapping of the service account tokens in service account configuration and enable it only for pods that need to use them.
  - _Fix:_ Disable automatic mounting of service account tokens to pods either at the service account level or at the individual pod level, by specifying the automountServiceAccountToken: false. Note that pod level takes precedence.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0034-automaticmappingofserviceaccount.json)
- `kubescape` **C-0282** · MEDIUM · CIS cis-aks-t1.8.0:4.1.12; cis-eks-t1.8.0:4.1.12; cis-v1.10.0:5.1.13; cis-v1.12.0:5.1.13 — Minimize access to the service account token creation
  - _What:_ Users with rights to create new service account tokens at a cluster level, can create long-lived privileged credentials in the cluster. This could allow for privilege escalation and persistent access to the cluster, even if the users account has been revoked.
  - _Fix:_ Where possible, remove access to the token sub-resource of serviceaccount objects.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0282-minimizeaccesstoserviceaccountcreate.json)
- `kyverno` **deny-secret-service-account-token-type** · MEDIUM — Deny Secret Service Account Token Type
  - _What:_ Before version 1.24, Kubernetes automatically generated Secret-based tokens for ServiceAccounts. When creating a Secret, you can specify its type using the type field of the Secret resource . The type kubernetes.io/service-account-token is used for legacy ServiceAccount tokens . These legacy Tokens can be of security concern and should be audited.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/deny-secret-service-account-token-type/deny-secret-service-account-token-type.yaml)
- `kyverno` **no-secrets** · MEDIUM — Disallow all Secrets
  - _What:_ Secrets often contain sensitive information which not all Pods need consume. This policy disables the use of all Secrets in a Pod definition. In order to work effectively, this Policy needs a separate Policy or rule to require `automountServiceAccountToken=false` at the Pod level or ServiceAccount level since this would otherwise result in a Secret being mounted.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/disallow-all-secrets/disallow-all-secrets.yaml)
- `trivy` **KSV-0036** · MEDIUM — Protecting Pod service account tokens
  - _What:_ ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false
  - _Fix:_ Disable the mounting of service account secret token by setting automountServiceAccountToken to false
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/protecting_pod_service_account_tokens.rego)
- `kyverno` **restrict-secrets-by-name** — Restrict Secrets by Name
  - _What:_ Secrets often contain sensitive information and their access should be carefully controlled. Although Kubernetes RBAC can be effective at restricting them in several ways, it lacks the ability to use wildcards in resource names. This policy ensures that only Secrets beginning with the name `safe-` can be consumed by Pods. In order to work effectively, this policy needs to be paired with a …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-secrets-by-name/restrict-secrets-by-name.yaml)

### TLS / certificates / ciphers  
_1 rules · tools: kubescape_

- `kubescape` **C-0286** · MEDIUM · manual · CIS cis-gke-v1.9.0:5.8.1; cis-v1.10.0:3.1.1; cis-v1.12.0:3.1.1 — Client certificate authentication should not be used for users
  - _What:_ Kubernetes provides the option to use client certificates for user authentication. However as there is no way to revoke these certificates when a user leaves an organization or loses their credential, they are not suitable for this purpose. It is not possible to fully disable client certificate use within a cluster as it is used for component to component authentication.
  - _Fix:_ Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of client certificates.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0286-clientcertificateauthenticationshouldnotbeusedforusers.json)

### hostPath volumes  
_2 rules · tools: kyverno_

- `kyverno` **limit-hostpath-type-pv** · MEDIUM — Limit hostPath PersistentVolumes to Specific Directories
  - _What:_ hostPath persistentvolumes consume the underlying node's file system. If hostPath volumes are not to be universally disabled, they should be restricted to only certain host paths so as not to allow access to sensitive information. This policy ensures the only directory that can be mounted as a hostPath volume is /data.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/limit-hostpath-type-pv/limit-hostpath-type-pv.yaml)
- `kyverno` **limit-hostpath-vols** · MEDIUM — Limit hostPath Volumes to Specific Directories
  - _What:_ hostPath volumes consume the underlying node's file system. If hostPath volumes are not to be universally disabled, they should be restricted to only certain host paths so as not to allow access to sensitive information. This policy ensures the only directory that can be mounted as a hostPath volume is /data. It is strongly recommended to pair this policy with a second to ensure readOnly access …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/limit-hostpath-vols/limit-hostpath-vols.yaml)

### Other  
_18 rules · tools: checkov, kube-bench, kube-linter, kubescape, trivy_

- `trivy` **KSV-0046** · CRITICAL — Manage all resources
  - _What:_ Full control of the cluster resources, and therefore also root on all nodes where workloads can run and has access to all pods, secrets, and data.
  - _Fix:_ Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_all_resources.rego)
- `trivy` **KSV-0114** · CRITICAL — Manage webhookconfigurations
  - _What:_ Webhooks can silently intercept or actively mutate/block resources as they are being created or updated. This includes secrets and pod specs.
  - _Fix:_ Remove webhook configuration resources/verbs, acceptable values for verbs ['get', 'list', 'watch']
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manage_webhook_configurations.rego)
- `kubescape` **C-0015** · HIGH — List Kubernetes secrets
  - _What:_ Attackers who have permissions to access secrets can access sensitive information that might include credentials to various services. This control determines which user, group or service account can list/get secrets.
  - _Fix:_ Monitor and approve list of users, groups and service accounts that can access secrets. Use exception mechanism to prevent repetitive the notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0015-listkubernetessecrets.json)
- `kubescape` **C-0255** · HIGH — Workload with secret access
  - _What:_ This control identifies workloads that have mounted secrets. Workloads with secret access can potentially expose sensitive information and increase the risk of unauthorized access to critical resources.
  - _Fix:_ Review the workloads identified by this control and assess whether it's necessary to mount these secrets. Remove secret access from workloads that don't require it or ensure appropriate access controls are in place to protect sensitive information.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0255-workloadwithsecretaccess.json)
- `kubescape` **C-0259** · HIGH — Workload with credential access
  - _What:_ This control checks if workloads specifications have sensitive information in their environment variables.
  - _Fix:_ Use Kubernetes secrets or Key Management Systems to store credentials.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0259-workloadwithcredentialaccess.json)
- `trivy` **KSV-0109** · HIGH — ConfigMap with secrets
  - _What:_ Storing secrets in configMaps is unsafe
  - _Fix:_ Remove password/secret from configMap data value
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/configMap_with_secrets.rego)
- `kubescape` **C-0020** · MEDIUM — Mount service principal
  - _What:_ When a cluster is deployed in the cloud, in some cases attackers can leverage their access to a container in the cluster to gain cloud credentials. This control determines if any workload contains a volume with potential access to cloud credential.
  - _Fix:_ Refrain from using path mount to known cloud credentials folders or files .
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0020-mountserviceprincipal.json)
- `kubescape` **C-0186** · MEDIUM · CIS cis-aks-t1.2.0:4.1.2; cis-aks-t1.8.0:4.1.2; cis-eks-t1.7.0:4.1.2; cis-eks-t1.8.0:4.1.2; cis-gke-v1.9.0:4.1.2; cis-v1.10.0:5.1.2; cis-v1.12.0:5.1.2 — Minimize access to secrets
  - _What:_ The Kubernetes API stores secrets, which may be service account tokens for the Kubernetes API or credentials used by workloads in the cluster. Access to these secrets should be restricted to the smallest possible group of users to reduce the risk of privilege escalation.
  - _Fix:_ Where possible, remove `get`, `list` and `watch` access to `secret` objects in the cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0186-minimizeaccesstosecrets.json)
- `kubescape` **C-0188** · MEDIUM · CIS cis-aks-t1.2.0:4.1.4; cis-aks-t1.8.0:4.1.4; cis-eks-t1.7.0:4.1.4; cis-eks-t1.8.0:4.1.4; cis-v1.10.0:5.1.4; cis-v1.12.0:5.1.4 — Minimize access to create pods
  - _What:_ The ability to create pods in a namespace can provide a number of opportunities for privilege escalation, such as assigning privileged service accounts to these pods or mounting hostPaths with access to sensitive data (unless Pod Security Policies are implemented to restrict this access) As such, access to create new pods should be restricted to the smallest possible group of users.
  - _Fix:_ Where possible, remove `create` access to `pod` objects in the cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0188-minimizeaccesstocreatepods.json)
- `kubescape` **C-0257** · MEDIUM — Workload with PVC access
  - _What:_ This control detects workloads that have mounted PVC. Workloads with PVC access can potentially expose sensitive information and elevate the risk of unauthorized access to critical resources.
  - _Fix:_ Review the workloads identified by this control and assess whether it's necessary to mount these PVCs. Remove PVC access from workloads that don't require it or ensure appropriate access controls are in place to protect sensitive information.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0257-pvcaccess.json)
- `kubescape` **C-0258** · MEDIUM — Workload with ConfigMap access
  - _What:_ This control detects workloads that have mounted ConfigMaps. Workloads with ConfigMap access can potentially expose sensitive information and elevate the risk of unauthorized access to critical resources.
  - _Fix:_ Review the workloads identified by this control and assess whether it's necessary to mount these configMaps. Remove configMaps access from workloads that don't require it or ensure appropriate access controls are in place to protect sensitive information.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0258-configmapaccess.json)
- `kubescape` **C-0264** · MEDIUM — PersistentVolume without encyption
  - _What:_ This control detects PersistentVolumes without encyption
  - _Fix:_ Enable encryption on the PersistentVolume using the configuration in StorageClass
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0264-pv-encrypted.json)
- `trivy` **KSV-01010** · MEDIUM — ConfigMap with sensitive content
  - _What:_ Storing sensitive content such as usernames and email addresses in configMaps is unsafe
  - _Fix:_ Remove sensitive content from configMap data value
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/configmap_with_sensitive.rego)
- `checkov` **CKV2_K8S_5** — No ServiceAccount/Node should be able to read all secrets
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/ReadAllSecrets.yaml)
- `kube-bench` **5.1.2** · manual · CIS cis-1.11:5.1.2 — Minimize access to secrets
  - _What:_ [RBAC and Service Accounts] Minimize access to secrets
  - _Fix:_ Where possible, remove get, list and watch access to Secret objects in the cluster.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.4.2** · manual · CIS cis-1.11:5.4.2 — Consider external secret storage
  - _What:_ [Secrets Management] Consider external secret storage
  - _Fix:_ Refer to the Secrets management options offered by your cloud provider or a third-party secrets management solution.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **env-value-from** — Env value from
  - _What:_ Indicates when objects use a secret or configmap not included in the deployment.
  - _Fix:_ Change the name or key to match a secret / configmap in the deployment.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/env-var-value-from.yaml)
- `kube-linter` **sensitive-host-mounts** — Sensitive host mounts
  - _What:_ Alert on deployments with sensitive host system directories mounted in containers
  - _Fix:_ Ensure sensitive host system directories are not mounted in containers by removing those Volumes and VolumeMounts.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/host-mounts.yaml)


## Supply chain & images

### Allowed / trusted registries  
_8 rules · tools: gatekeeper, kubescape, kyverno, trivy_

- `kubescape` **C-0313** · HIGH — Agent runtime image registries
  - _What:_ Images used by Agent Sandbox and Agent Substrate resources should originate from an explicitly allowed registry.
  - _Fix:_ Use an image registry listed in imageRepositoryAllowList.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0313-agent-runtime-image-registries.json)
- `kubescape` **C-0253** · MEDIUM — Deprecated Kubernetes image registry
  - _What:_ Kubernetes team has deprecated GCR (k8s.gcr.io) registry and recommends pulling Kubernetes components from the new registry (registry.k8s.io). This is mandatory from 1.27
  - _Fix:_ Change the images to be pulled from the new registry (registry.k8s.io).
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0253-deprecated-k8s-registry.json)
- `kyverno` **advanced-restrict-image-registries** · MEDIUM — Advanced Restrict Image Registries in CEL expressions
  - _What:_ This policy restricts Pod images to approved registries defined globally in a ConfigMap as a single string, newline-separated list, or YAML list with hyphens, and optionally at the Namespace level via annotations. Uses contains() for compatibility with Kyverno 1.14.0.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/advanced-restrict-image-registries/advanced-restrict-image-registries.yaml)
- `kyverno` **allowed-image-repos** · MEDIUM — Allowed Image Repositories
  - _What:_ In addition to restricting the image registry from which images are pulled, in some cases and environments it may be required to also restrict which image repositories are used, for example in some restricted Namespaces. This policy ensures that the only allowed image repositories present in a given Pod, across any container type, come from the designated list.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/allowed-image-repos/allowed-image-repos.yaml)
- `trivy` **KSV-0125** · MEDIUM — Restrict container images to trusted registries
  - _What:_ Ensure that all containers use images only from trusted registry domains.
  - _Fix:_ Use images from trusted registries.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/uses_untrusted_registry.rego)
- `gatekeeper` **k8sallowedrepos** — Allowed Repositories
  - _What:_ Requires container images to begin with a string from the specified list. To prevent bypasses, ensure a '/' is added when specifying DockerHub repositories or custom registries. If exact matches or glob-like syntax are preferred, use the k8sallowedreposv2 policy.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/allowedrepos/template.yaml)
- `gatekeeper` **k8sallowedreposv2** — Allowed Images
  - _What:_ This policy enforces that container images must begin with a string from a specified list. The updated version, K8sAllowedReposv2, introduces support for exact match and glob-like syntax to enhance security: 1. Exact Match: By default, if the * character is not specified, the policy strictly checks for an exact match of the full registry, repository, and/or the image name. 2. Glob-like Syntax: …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/allowedreposv2/template.yaml)
- `gatekeeper` **k8sdisallowedrepos** — Disallowed Repositories
  - _What:_ Disallowed container repositories that begin with a string from the specified list.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/disallowedrepos/template.yaml)

### Image pull policy  
_3 rules · tools: checkov, kyverno, polaris_

- `kyverno` **imagepullpolicy-always** · MEDIUM — Require imagePullPolicy Always
  - _What:_ If the `latest` tag is allowed for images, it is a good idea to have the imagePullPolicy field set to `Always` to ensure should that tag be overwritten that future pulls will get the updated image. This policy validates the imagePullPolicy is set to `Always` when the `latest` tag is specified explicitly or where a tag is not defined at all.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/imagepullpolicy-always/imagepullpolicy-always.yaml)
- `polaris` **pullPolicyNotAlways** · MEDIUM — Image pull policy should be "Always"
  - _What:_ Pass: Image pull policy is "Always" | Fail: Image pull policy should be "Always"
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/pullPolicyNotAlways.yaml)
- `checkov` **CKV_K8S_15** — Image Pull Policy should be Always
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ImagePullPolicyAlways.py)

### Image signing & verification  
_3 rules · tools: kubescape, kyverno_

- `kubescape` **C-0236** · HIGH — Verify image signature
  - _What:_ Verifies the signature of each image with given public keys
  - _Fix:_ Replace the image with an image that is signed correctly
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0236-verifyimagesignature.json)
- `kubescape` **C-0237** · HIGH — Check if signature exists
  - _What:_ Ensures that all images contain some signature
  - _Fix:_ Replace the image with a signed image
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0237-hasimagesignature.json)
- `kyverno` **verify-slsa-provenance-keyless** · MEDIUM — Verify SLSA Provenance (Keyless)
  - _What:_ Provenance is used to identify how an artifact was produced and from where it originated. SLSA provenance is an industry-standard method of representing that provenance. This policy verifies that an image has SLSA provenance and was signed by the expected subject and issuer when produced through GitHub Actions. It requires configuration based upon your own values.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-ivpol/verify-image-slsa/verify-image-slsa.yaml)

### Image tag / digest pinning  
_11 rules · tools: checkov, gatekeeper, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0304** · HIGH — Agent Sandbox image provenance
  - _What:_ Ensure Agent Sandbox SandboxTemplate resources use container images from approved registries and pin images to explicit version tags or digests, rejecting the mutable :latest tag.
  - _Fix:_ Update SandboxTemplate container images to use an approved registry from the imageRepositoryAllowList, and pin each image to an explicit version tag (e.g. :1.2.3) or digest reference (e.g. @sha256:...).
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0304-agentsandboximageprovenance.json)
- `kubescape` **C-0312** · HIGH — Agent runtime image digest pinning
  - _What:_ Images used by Agent Sandbox and Agent Substrate resources should be pinned to an exact SHA-256 digest.
  - _Fix:_ Use image references ending in @sha256: followed by exactly 64 lowercase hexadecimal characters.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0312-agent-runtime-image-digests.json)
- `polaris` **tagNotSpecified** · HIGH — Image tag should be specified
  - _What:_ Pass: Image tag is specified | Fail: Image tag should be specified
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/tagNotSpecified.yaml)
- `kyverno` **disallow-latest-tag** · MEDIUM — Disallow Latest Tag in VPOL
  - _What:_ The ':latest' tag is mutable and can lead to unexpected errors if the image changes. A best practice is to use an immutable tag that maps to a specific version of an application Pod. This policy validates that the image specifies a tag and that it is not called `latest`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/disallow-latest-tag/disallow-latest-tag.yaml)
- `prowler` **core_image_tag_fixed** · MEDIUM — Container images use fixed tags
  - _What:_ **Kubernetes Pods** are evaluated for containers using images without a **fixed version tag**, such as `latest` or no tag at all, which results in unpredictable image versions being pulled.
  - _Fix:_ Pin all container images to a **specific version tag** or **digest** (`@sha256:...`) to ensure reproducible, auditable deployments. - Avoid `latest` and untagged images in production - Use **image digests** for maximum immutability - Enforce tag policies with **admission controllers** (e.g., OPA …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_image_tag_fixed/core_image_tag_fixed.metadata.json)
- `trivy` **KSV-0013** · MEDIUM — Image tag ":latest" used
  - _What:_ It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.
  - _Fix:_ Use a specific container image tag that is not 'latest'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/uses_image_tag_latest.rego)
- `checkov` **CKV_K8S_14** — Image Tag should be fixed - not latest or blank
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ImageTagFixed.py)
- `checkov` **CKV_K8S_43** — Image should use digest
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ImageDigest.py)
- `gatekeeper` **k8sdisallowedtags** — Disallow tags
  - _What:_ Requires container images to have an image tag different from the ones in the specified list. https://kubernetes.io/docs/concepts/containers/images/#image-names
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/disallowedtags/template.yaml)
- `gatekeeper` **k8simagedigests** — Image Digests
  - _What:_ Requires container images to contain a digest. https://kubernetes.io/docs/concepts/containers/images/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/imagedigests/template.yaml)
- `kube-linter` **latest-tag** — Latest tag
  - _What:_ Indicates when a deployment-like object is running a container with an invalid container image
  - _Fix:_ Use a container image with a specific tag other than latest.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/latest-tag.yaml)

### Run as non-root user  
_1 rules · tools: trivy_

- `trivy` **KSV-0012** · MEDIUM — Runs as root user
  - _What:_ Force the running image to run as a non-root user to ensure least privileges.
  - _Fix:_ Set 'containers[].securityContext.runAsNonRoot' to true.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runs_as_root.rego)

### Other  
_7 rules · tools: kubescape, kyverno, trivy_

- `trivy` **KSV-0124** · HIGH — Gatekeeper repo reference is ambiguously open-ended
  - _What:_ A Gatekeeper policy that references image repositories for prefix-matching is using open-ended and ambiguous pattern, and can potentially match unintended repositories.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/repo_ambiguous_prefix.rego)
- `kubescape` **C-0085** · MEDIUM — Workloads with excessive amount of vulnerabilities
  - _What:_ Container images with multiple Critical and High sevirity vulnerabilities increase the risk of potential exploit. This control lists all such images according to the threashold provided by the customer.
  - _Fix:_ Update your workload images as soon as possible when fixes become available.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0085-workloadswithexcessiveamountofvulnerabilities.json)
- `kyverno` **allowed-base-images** · MEDIUM — Allowed Base Images
  - _What:_ Building images which specify a base as their origin is a good start to improving supply chain security, but over time organizations may want to build an allow list of specific base images which are allowed to be used when constructing containers. This policy ensures that a container's base, found in an OCI annotation, is in a cluster-wide allow list.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/allowed-base-images/allowed-base-images.yaml)
- `kyverno` **block-images-with-volumes** · MEDIUM — Block Images with Volumes
  - _What:_ OCI images may optionally be built with VOLUME statements which, if run in read-only mode, would still result in write access to the specified location. This may be unexpected and undesirable. This policy checks the contents of every container image and inspects them for such VOLUME statements, then blocks if found.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-images-with-volumes/block-images-with-volumes.yaml)
- `kyverno` **block-large-images** · MEDIUM — Block Large Images
  - _What:_ Pods which run containers of very large image size take longer to pull and require more space to store. A user may either inadvertently or purposefully name an image which is unusually large to disrupt operations. This policy checks the size of every container image and blocks if it is over 2 Gibibytes.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-large-images/block-large-images.yaml)
- `kyverno` **block-stale-images** · MEDIUM — Block Stale Images
  - _What:_ This policy blocks pods that use container images built more than 6 months ago to ensure deployments use recent, maintained images.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-stale-images/block-stale-images.yaml)
- `kyverno` **require-image-checksum** · MEDIUM — Require Images Use Checksums
  - _What:_ Use of a SHA checksum when pulling an image is often preferable because tags are mutable and can be overwritten. This policy checks to ensure that all images use SHA checksums rather than tags.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/require-image-checksum/require-image-checksum.yaml)


## Worker nodes: kubelet & kube-proxy

### API / kubelet authn & authz flags  
_15 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `trivy` **KCV-0079** · CRITICAL — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [kubelet] Disable anonymous requests to the Kubelet server.
  - _Fix:_ Disable anonymous requests to the Kubelet server
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_anonymous_auth_argument.rego)
- `kubescape` **C-0172** · HIGH · CIS cis-aks-t1.2.0:3.2.1; cis-aks-t1.8.0:3.2.1; cis-eks-t1.7.0:3.2.1; cis-eks-t1.8.0:3.2.1; cis-v1.10.0:4.2.1; cis-v1.12.0:4.2.1 — Ensure that the --anonymous-auth argument is set to false
  - _What:_ Disable anonymous requests to the Kubelet server.
  - _Fix:_ If using a Kubelet config file, edit the file to set `authentication: anonymous: enabled` to `false`. If using executable arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_SYSTEM_PODS_ARGS` variable. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0172-ensurethattheanonymousauthargumentissettofalse.json)
- `prowler` **kubelet_authorization_mode** · HIGH — Kubelet --authorization-mode is not set to AlwaysAllow
  - _What:_ **Kubernetes Kubelet** authorization configuration is inspected to confirm the mode is not `AlwaysAllow`. *If authorization settings are absent, the effective mode requires manual verification.*
  - _Fix:_ Use kubelet authorization mode `Webhook` so decisions defer to **RBAC**. Apply **least privilege** on node subresources, disable anonymous access, and restrict network exposure of the kubelet endpoint. Employ **defense in depth** with TLS and audit to monitor and control access. Steps: 1. In your …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_authorization_mode/kubelet_authorization_mode.metadata.json)
- `trivy` **KCV-0080** · HIGH — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [kubelet] Do not allow all requests. Enable explicit authorization.
  - _Fix:_ edit Kubelet config and set authorization: mode to Webhook.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_authorization_mode_argument.rego)
- `trivy` **KCV-0082** · HIGH — Verify that the --read-only-port argument is set to 0
  - _What:_ [kubelet] Disable the read-only port.
  - _Fix:_ Disable the read-only port
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_read_only_port_argument.rego)
- `kubescape` **C-0119** · MEDIUM · CIS cis-v1.10.0:1.2.7; cis-v1.12.0:1.2.7 — Ensure that the API Server --authorization-mode argument includes Node
  - _What:_ Restrict kubelet nodes to reading only objects associated with them.
  - _Fix:_ Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--authorization-mode` parameter to a value that includes `Node`. ``` --authorization-mode=Node,RBAC ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0119-ensurethattheapiserverauthorizationmodeargumentincludesnode.json)
- `kubescape` **C-0175** · MEDIUM · CIS cis-aks-t1.2.0:3.2.4; cis-aks-t1.8.0:3.2.4; cis-eks-t1.7.0:3.2.4; cis-eks-t1.8.0:3.2.4; cis-v1.10.0:4.2.4; cis-v1.12.0:4.2.4 — Verify that the --read-only-port argument is set to 0
  - _What:_ Disable the read-only port.
  - _Fix:_ If using a Kubelet config file, edit the file to set `readOnlyPort` to `0`. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_SYSTEM_PODS_ARGS` variable. ``` --read-only-port=0 ``` Based on your …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0175-verifythatthereadonlyportargumentissetto0.json)
- `prowler` **kubelet_disable_read_only_port** · MEDIUM — Kubelet read-only port is disabled (set to 0)
  - _What:_ **Kubernetes Kubelet** configuration is inspected for the `readOnlyPort` setting and whether it is set to `0` to disable the unauthenticated HTTP endpoint.
  - _Fix:_ Disable the unauthenticated endpoint by setting `readOnlyPort: 0`. Apply **least privilege**: expose only the TLS-authenticated kubelet endpoint, enforce authorization, and restrict network access to kubelet with host firewalls or network policies. Monitor nodes for unexpected open ports. Steps: …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_disable_read_only_port/kubelet_disable_read_only_port.metadata.json)
- `trivy` **KCV-0008** · LOW — Ensure that the --authorization-mode argument includes Node
  - _What:_ [API server] Restrict kubelet nodes to reading only objects associated with them.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes Node.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_authorization_mode_includes_node.rego)
- `checkov` **CKV_K8S_138** · CIS cis-1.6:4.2.1 — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [kubelet] Ensure that the --anonymous-auth argument is set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletAnonymousAuth.py)
- `checkov` **CKV_K8S_139** · CIS cis-1.6:4.2 — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [kubelet] Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletAuthorizationModeNotAlwaysAllow.py)
- `checkov` **CKV_K8S_141** · CIS cis-1.6:4.2.4 — Ensure that the --read-only-port argument is set to 0
  - _What:_ [kubelet] Ensure that the --read-only-port argument is set to 0
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletReadOnlyPort.py)
- `kube-bench` **4.2.1** · CIS cis-1.11:4.2.1 — Ensure that the --anonymous-auth argument is set to false
  - _What:_ [Kubelet] Ensure that the --anonymous-auth argument is set to false
  - _Fix:_ If using a Kubelet config file, edit the file to set `authentication: anonymous: enabled` to `false`. If using executable arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. `--anonymous-auth=false` Based on …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.2** · CIS cis-1.11:4.2.2 — Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _What:_ [Kubelet] Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - _Fix:_ If using a Kubelet config file, edit the file to set `authorization.mode` to Webhook. If using executable arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_AUTHZ_ARGS variable. --authorization-mode=Webhook Based on your system, restart …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.4** · manual · CIS cis-1.11:4.2.4 — Verify that if defined, the --read-only-port argument is set to 0
  - _What:_ [Kubelet] Verify that if defined, the --read-only-port argument is set to 0
  - _Fix:_ If using a Kubelet config file, edit the file to set `readOnlyPort` to 0. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. --read-only-port=0 Based on your system, restart the kubelet …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)

### Admission plugins  
_3 rules · tools: kubescape, prowler, trivy_

- `prowler` **apiserver_node_restriction_plugin** · HIGH — API server pod has NodeRestriction admission control plugin enabled
  - _What:_ **Kubernetes API server** has the **NodeRestriction** admission controller enabled via `--enable-admission-plugins`. This setting confines kubelets to modify only their own `Node` object and bound `Pod` objects.
  - _Fix:_ Enable the **NodeRestriction** admission controller to enforce **least privilege** for kubelets. Pair it with **Node** and **RBAC** authorization, strong kubelet identity, and audit monitoring for defense-in-depth. Regularly rotate credentials and limit kubelet access to only its node. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_node_restriction_plugin/apiserver_node_restriction_plugin.metadata.json)
- `kubescape` **C-0127** · MEDIUM · CIS cis-v1.10.0:1.2.14; cis-v1.12.0:1.2.14 — Ensure that the admission control plugin NodeRestriction is set
  - _What:_ Limit the `Node` and `Pod` objects that a kubelet could modify.
  - _Fix:_ Follow the Kubernetes documentation and configure `NodeRestriction` plug-in on kubelets. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the `--enable-admission-plugins` parameter to a value that includes …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0127-ensurethattheadmissioncontrolpluginnoderestrictionisset.json)
- `trivy` **KCV-0016** · LOW — Ensure that the admission control plugin NodeRestriction is set
  - _What:_ [API server] Limit the Node and Pod objects that a kubelet could modify.
  - _Fix:_ Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_node_restriction_plugin.rego)

### Allowed / trusted registries  
_1 rules · tools: kubescape_

- `kubescape` **C-0249** · MEDIUM · manual · CIS cis-aks-t1.2.0:5.6.1; cis-aks-t1.8.0:5.6.1 — Restrict untrusted workloads
  - _What:_ Restricting unstrusted workloads can be achieved by using ACI along with AKS. What is ACI? ACI lets you quickly deploy container instances without additional infrastructure overhead. When you connect with AKS, ACI becomes a secured, logical extension of your AKS cluster. The virtual nodes component, which is based on Virtual Kubelet, is installed in your AKS cluster that presents ACI as a …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0249-restrictuntrustedworkloads.json)

### Audit logging  
_1 rules · tools: kubescape_

- `kubescape` **C-0254** · MEDIUM · manual · CIS cis-aks-t1.2.0:2.1.1; cis-aks-t1.8.0:2.1.1 — Enable audit Logs
  - _What:_ With Azure Kubernetes Service (AKS), the control plane components such as the kube-apiserver and kube-controller-manager are provided as a managed service. You create and manage the nodes that run the kubelet and container runtime, and deploy your applications through the managed Kubernetes API server. To help troubleshoot your application and services, you may need to view the logs generated by …
  - _Fix:_ Azure audit logs are enabled and managed in the Azure portal. To enable log collection for the Kubernetes master components in your AKS cluster, open the Azure portal in a web browser and complete the following steps: 1. Select the resource group for your AKS cluster, such as myResourceGroup. …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0254-enableauditlogs.json)

### File permissions / ownership  
_3 rules · tools: kubescape, prowler_

- `prowler` **kubelet_config_yaml_ownership** · HIGH — Node kubelet config.yaml file ownership is root:root
  - _What:_ **Kubernetes Kubelet** configuration file `config.yaml` (e.g., `/var/lib/kubelet/config.yaml`) is evaluated to confirm ownership by `root:root` when the kubelet uses a config file via `--config`.
  - _Fix:_ Enforce `root:root` ownership with restrictive permissions on the kubelet config. Apply **least privilege** and **separation of duties** so only trusted admins/processes can write. Use centralized, immutable configuration, monitor with integrity/audit logs, and limit interactive access to nodes …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_config_yaml_ownership/kubelet_config_yaml_ownership.metadata.json)
- `prowler` **kubelet_service_file_ownership_root** · HIGH — Kubelet service file on the node is owned by root:root
  - _What:_ **Kubernetes Kubelet service configuration** on each node is expected to be owned by **root**. This assessment inspects the systemd drop-in at `/etc/systemd/system/kubelet.service.d/kubeadm.conf` and expects ownership `root:root`, ensuring only privileged users can modify kubelet startup settings.
  - _Fix:_ Apply **least privilege** to node config: ensure the kubelet service file is `root:root` and writable only by root. Use **configuration management** to enforce permissions and detect drift, enable **file integrity monitoring**, harden the OS, and restrict privileged node access with **separation …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_service_file_ownership_root/kubelet_service_file_ownership_root.metadata.json)
- `kubescape` **C-0279** · MEDIUM · CIS cis-aks-t1.8.0:4.1.9; cis-eks-t1.8.0:4.1.10; cis-v1.10.0:5.1.10; cis-v1.12.0:5.1.10 — Minimize access to the proxy sub-resource of nodes
  - _What:_ Users with access to the Proxy sub-resource of Node objects automatically have permissions to use the Kubelet API, which may allow for privilege escalation or bypass cluster security controls such as audit logs.
  - _Fix:_ Where possible, remove access to the proxy sub-resource of node objects.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0279-minimizeaccesstonodeproxy.json)

### Image tag / digest pinning  
_1 rules · tools: kubescape_

- `kubescape` **C-0306** · LOW — Images not pinned to digest
  - _What:_ Fails if a container image reference is not pinned to an immutable digest (image@sha256:...). Pinning makes the image reference immutable, closing the TOCTOU window where an image signature (C-0236) is verified against a mutable tag that can be re-pointed after verification, causing the kubelet to pull something that was never verified.
  - _Fix:_ Pin container images to an immutable digest (image@sha256:...).
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0306-imagenotpinnedtodigest.json)

### Kubelet hardening flags  
_18 rules · tools: checkov, kube-bench, kubescape, trivy_

- `trivy` **KCV-0083** · HIGH — Ensure that the --protect-kernel-defaults is set to true
  - _What:_ [kubelet] Protect tuned kernel parameters from overriding kubelet default kernel parameter values.
  - _Fix:_ If using a Kubelet config file, edit the file to set protectKernelDefaults: true
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_protect_kernel_defaults.rego)
- `trivy` **KCV-0084** · HIGH — Ensure that the --make-iptables-util-chains argument is set to true
  - _What:_ [kubelet] Allow Kubelet to manage iptables.
  - _Fix:_ If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_make_iptables_util_chains.rego)
- `trivy` **KCV-0085** · HIGH — Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - _What:_ [kubelet] Do not disable timeouts on streaming connections.
  - _Fix:_ Edit the kubelet service file /etc/kubernetes/kubelet.conf and set --streaming-connection-idle-timeout=5m
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_streaming_connection_argument.rego)
- `trivy` **KCV-0086** · HIGH — Ensure that the --hostname-override argument is not set
  - _What:_ [kubelet] Do not override node hostnames.
  - _Fix:_ Edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove the --hostname-override argument
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_hostname_override.rego)
- `trivy` **KCV-0087** · HIGH — Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture
  - _What:_ [kubelet] Security relevant information should be captured. The --event-qps flag on the Kubelet can be used to limit the rate at which events are gathered
  - _Fix:_ If using a Kubelet config file, edit the file to set eventRecordQPS: to an appropriate level. If using command line arguments, edit the kubelet service file
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_event_qps.rego)
- `kubescape` **C-0176** · LOW · CIS cis-aks-t1.2.0:3.2.5; cis-aks-t1.8.0:3.2.5; cis-eks-t1.7.0:3.2.5; cis-eks-t1.8.0:3.2.5; cis-v1.10.0:4.2.5; cis-v1.12.0:4.2.5 — Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - _What:_ Do not disable timeouts on streaming connections.
  - _Fix:_ If using a Kubelet config file, edit the file to set `streamingConnectionIdleTimeout` to a value other than 0. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_SYSTEM_PODS_ARGS` variable. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0176-ensurethatthestreamingconnectionidletimeoutargumentisnotsetto0.json)
- `kubescape` **C-0177** · LOW · CIS cis-aks-t1.2.0:3.2.6; cis-aks-t1.8.0:3.2.6 — Ensure that the --protect-kernel-defaults argument is set to true
  - _What:_ Protect tuned kernel parameters from overriding kubelet default kernel parameter values.
  - _Fix:_ If using a Kubelet config file, edit the file to set `protectKernelDefaults: true`. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_SYSTEM_PODS_ARGS` variable. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0177-ensurethattheprotectkerneldefaultsargumentissettotrue.json)
- `kubescape` **C-0178** · LOW · CIS cis-aks-t1.2.0:3.2.7; cis-aks-t1.8.0:3.2.7; cis-eks-t1.7.0:3.2.6; cis-eks-t1.8.0:3.2.6; cis-v1.10.0:4.2.6; cis-v1.12.0:4.2.6 — Ensure that the --make-iptables-util-chains argument is set to true
  - _What:_ Allow Kubelet to manage iptables.
  - _Fix:_ If using a Kubelet config file, edit the file to set `makeIPTablesUtilChains: true`. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and remove the `--make-iptables-util-chains` argument from the `KUBELET_SYSTEM_PODS_ARGS` variable. …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0178-ensurethatthemakeiptablesutilchainsargumentissettotrue.json)
- `kubescape` **C-0179** · LOW · CIS cis-aks-t1.2.0:3.2.8; cis-aks-t1.8.0:3.2.8; cis-v1.10.0:4.2.7; cis-v1.12.0:4.2.7 — Ensure that the --hostname-override argument is not set
  - _What:_ Do not override node hostnames.
  - _Fix:_ Edit the kubelet service file `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` on each worker node and remove the `--hostname-override` argument from the `KUBELET_SYSTEM_PODS_ARGS` variable. Based on your system, restart the `kubelet` service. For example: ``` systemctl daemon-reload …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0179-ensurethatthehostnameoverrideargumentisnotset.json)
- `kubescape` **C-0180** · LOW · CIS cis-aks-t1.2.0:3.2.9; cis-aks-t1.8.0:3.2.9; cis-eks-t1.7.0:3.2.7; cis-eks-t1.8.0:3.2.7; cis-v1.10.0:4.2.8; cis-v1.12.0:4.2.8 — Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture
  - _What:_ Security relevant information should be captured. The `--event-qps` flag on the Kubelet can be used to limit the rate at which events are gathered. Setting this too low could result in relevant events not being logged, however the unlimited setting of `0` could result in a denial of service on the kubelet.
  - _Fix:_ If using a Kubelet config file, edit the file to set `eventRecordQPS:` to an appropriate level. If using command line arguments, edit the kubelet service file `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` on each worker node and set the below parameter in `KUBELET_SYSTEM_PODS_ARGS` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0180-ensurethattheeventqpsargumentissetto0oralevelwhichensuresappropriateeventcapture.json)
- `checkov` **CKV_K8S_143** · CIS cis-1.6:4.2.5 — Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - _What:_ [kubelet] Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletStreamingConnectionIdleTimeout.py)
- `checkov` **CKV_K8S_144** · CIS cis-1.6:4.2.6 — Ensure that the --protect-kernel-defaults argument is set to true
  - _What:_ [kubelet] Ensure that the --protect-kernel-defaults argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletProtectKernelDefaults.py)
- `checkov` **CKV_K8S_145** · CIS cis-1.6:4.2.7 — Ensure that the --make-iptables-util-chains argument is set to true
  - _What:_ [kubelet] Ensure that the --make-iptables-util-chains argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletMakeIptablesUtilChains.py)
- `checkov` **CKV_K8S_146** · CIS cis-1.6:4.2.8 — Ensure that the --hostname-override argument is not set
  - _What:_ [kubelet] Ensure that the --hostname-override argument is not set
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletHostnameOverride.py)
- `checkov` **CKV_K8S_147** · CIS cis-1.6:4.2.9 — Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture
  - _What:_ [kubelet] Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubletEventCapture.py)
- `kube-bench` **4.2.5** · manual · CIS cis-1.11:4.2.5 — Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - _What:_ [Kubelet] Ensure that the --streaming-connection-idle-timeout argument is not set to 0
  - _Fix:_ If using a Kubelet config file, edit the file to set `streamingConnectionIdleTimeout` to a value other than 0. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.6** · CIS cis-1.11:4.2.6 — Ensure that the --make-iptables-util-chains argument is set to true
  - _What:_ [Kubelet] Ensure that the --make-iptables-util-chains argument is set to true
  - _Fix:_ If using a Kubelet config file, edit the file to set `makeIPTablesUtilChains` to `true`. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and remove the --make-iptables-util-chains argument from the KUBELET_SYSTEM_PODS_ARGS variable. Based on your …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.7** · manual · CIS cis-1.11:4.2.7 — Ensure that the --hostname-override argument is not set
  - _What:_ [Kubelet] Ensure that the --hostname-override argument is not set
  - _Fix:_ Edit the kubelet service file $kubeletsvc on each worker node and remove the --hostname-override argument from the KUBELET_SYSTEM_PODS_ARGS variable. Based on your system, restart the kubelet service. For example, systemctl daemon-reload systemctl restart kubelet.service
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)

### Liveness / readiness probes  
_1 rules · tools: kyverno_

- `kyverno` **require-pod-probes** · MEDIUM — Require Pod Probes
  - _What:_ Liveness and readiness probes are essential for managing Pod lifecycle during deployments, restarts, and upgrades. Liveness probes help the kubelet determine when to restart containers, while readiness probes help Services and Deployments determine when Pods are ready to receive traffic. Startup probes provide additional control during container startup. This policy validates that all containers …
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-probes/require-probes.yaml)

### Seccomp  
_1 rules · tools: kube-bench_

- `kube-bench` **4.2.14** · manual · CIS cis-1.11:4.2.14 — Ensure that the --seccomp-default parameter is set to true
  - _What:_ [Kubelet] Ensure that the --seccomp-default parameter is set to true
  - _Fix:_ Set the parameter, either via the --seccomp-default command line parameter or the seccompDefault configuration file setting. By default the seccomp profile is not enabled.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)

### TLS / certificates / ciphers  
_42 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `kubescape` **C-0070** · CRITICAL — Enforce Kubelet client TLS authentication
  - _What:_ Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose.
  - _Fix:_ Start the kubelet with the --client-ca-file flag, providing a CA bundle to verify client certificates with.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0070-enforcekubeletclienttlsauthentication.json)
- `prowler` **apiserver_kubelet_cert_auth** · CRITICAL — API server pod has --kubelet-certificate-authority configured
  - _What:_ **Kubernetes API server** is configured with a **kubelet certificate authority** via `--kubelet-certificate-authority` so it can validate kubelet serving certificates during APIkubelet TLS connections.
  - _Fix:_ Enforce **mutual TLS** for API server-kubelet communication. Provide a trusted CA using `--kubelet-certificate-authority`, issue certs from controlled PKI, rotate keys, and limit client credentials per *least privilege*. Prefer private networking and layered controls for **defense in depth**. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_kubelet_cert_auth/apiserver_kubelet_cert_auth.metadata.json)
- `prowler` **apiserver_kubelet_tls_auth** · CRITICAL — API server pod has --kubelet-client-certificate and --kubelet-client-key arguments configured
  - _What:_ **Kubernetes API server** is configured to use **TLS client certificates** when communicating with kubelets via `--kubelet-client-certificate` and `--kubelet-client-key`.
  - _Fix:_ Enforce **mutual TLS** between apiserver and kubelets using a dedicated client certificate/key (`--kubelet-client-certificate`, `--kubelet-client-key`) signed by a trusted CA. Apply **least privilege** to kubelet authorization and disable **anonymous access** to strengthen defense-in-depth. Steps: …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_kubelet_tls_auth/apiserver_kubelet_tls_auth.metadata.json)
- `trivy` **KCV-0081** · CRITICAL — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ [kubelet] Enable Kubelet authentication using certificates.
  - _Fix:_ If using a Kubelet config file, edit the --client-ca-file argument ito appropriate value
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_client_ca_file_argument.rego)
- `trivy` **KCV-0088** · CRITICAL — Ensure that the --tls-cert-file argument are set as appropriate
  - _What:_ [kubelet] Setup TLS connection on the Kubelets.
  - _Fix:_ If using a Kubelet config file, edit the file to set tlsCertFile to the location
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_tls_cert_file.rego)
- `trivy` **KCV-0089** · CRITICAL — Ensure that the --tls-key-file argument are set as appropriate
  - _What:_ [kubelet] Setup TLS connection on the Kubelets.
  - _Fix:_ If using a Kubelet config file, edit the file to set tlskeyFile to the location
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_tls_key_file.rego)
- `trivy` **KCV-0092** · CRITICAL — Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
  - _What:_ [kubelet] Ensure that the Kubelet is configured to only use strong cryptographic ciphers.
  - _Fix:_ If using a Kubelet config file, edit the file to set TLSCipherSuites
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_only_use_strong_cryptographic.rego)
- `kubescape` **C-0116** · HIGH · CIS cis-v1.10.0:1.2.4; cis-v1.12.0:1.2.4 — Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - _What:_ Enable certificate based kubelet authentication.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets. Then, edit API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the kubelet client certificate and key parameters as below. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0116-ensurethattheapiserverkubeletclientcertificateandkubeletclientkeyargumentsaresetasappropriate.json)
- `kubescape` **C-0117** · HIGH · CIS cis-v1.10.0:1.2.5; cis-v1.12.0:1.2.5 — Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate
  - _What:_ Verify kubelet's certificate before establishing connection.
  - _Fix:_ Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the Control Plane node and set the `--kubelet-certificate-authority` parameter to the path to the …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0117-ensurethattheapiserverkubeletcertificateauthorityargumentissetasappropriate.json)
- `kubescape` **C-0181** · HIGH · CIS cis-eks-t1.7.0:3.2.8; cis-eks-t1.8.0:3.2.8; cis-v1.10.0:4.2.9; cis-v1.12.0:4.2.9 — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ Setup TLS connection on the Kubelets.
  - _Fix:_ If using a Kubelet config file, edit the file to set tlsCertFile to the location of the certificate file to use to identify this Kubelet, and tlsPrivateKeyFile to the location of the corresponding private key file. If using command line arguments, edit the kubelet service file …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0181-ensurethatthetlscertfileandtlsprivatekeyfileargumentsaresetasappropriate.json)
- `prowler` **kubelet_client_ca_file_set** · HIGH — Kubelet has a client CA file configured for authentication
  - _What:_ **Kubernetes Kubelet** is evaluated for X.509 client certificate authentication by checking if its config sets `authentication.x509.clientCAFile` to validate clients on the HTTPS endpoint.
  - _Fix:_ Enforce **mutual TLS** to the kubelet by providing a trusted `clientCAFile`. - Disable anonymous access - Delegate authorization to the API server with least-privilege RBAC - Restrict network exposure to the kubelet - Rotate certificates and monitor access *Use defense-in-depth across authn and …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_client_ca_file_set/kubelet_client_ca_file_set.metadata.json)
- `prowler` **kubelet_rotate_certificates** · HIGH — Kubelet client certificate rotation is enabled
  - _What:_ **Kubernetes Kubelet** configuration is inspected for client TLS credential rotation. The finding determines whether `rotateCertificates` is enabled so kubelets automatically renew the client certificates they use to authenticate to the API server.
  - _Fix:_ Enable **kubelet client certificate rotation** by setting `rotateCertificates: true`. Apply controlled CSR approval and monitor certificate health to ensure timely renewals. Prefer short-lived, automatically rotated credentials over static keys, aligning with **least privilege** and **defense in …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_rotate_certificates/kubelet_rotate_certificates.metadata.json)
- `prowler` **kubelet_tls_cert_and_key** · HIGH — Kubelet has TLS certificate and private key files configured
  - _What:_ **Kubernetes Kubelet** configuration includes a TLS serving certificate and private key defined by `tlsCertFile` and `tlsPrivateKeyFile` to secure its HTTPS endpoint.
  - _Fix:_ Provision a **CA-signed, node-unique** serving certificate and private key for each kubelet and set `tlsCertFile` and `tlsPrivateKeyFile`. Prefer automated issuance and rotation. Ensure clients validate the certificate and limit kubelet API exposure with network controls and RBAC, applying **least …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_tls_cert_and_key/kubelet_tls_cert_and_key.metadata.json)
- `trivy` **KCV-0090** · HIGH — Ensure that the --rotate-certificates argument is not set to false
  - _What:_ [kubelet] Enable kubelet client certificate rotation.
  - _Fix:_ If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_rotate_certificates.rego)
- `trivy` **KCV-0091** · HIGH — Verify that the RotateKubeletServerCertificate argument is set to true
  - _What:_ [kubelet] Enable kubelet server certificate rotation.
  - _Fix:_ Edit the kubelet service file /etc/kubernetes/kubelet.conf and set --feature-gates=RotateKubeletServerCertificate=true
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/kubelet_rotate_kubelet_server_certificate.rego)
- `kubescape` **C-0149** · MEDIUM · CIS cis-v1.10.0:1.3.6; cis-v1.12.0:1.3.6 — Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true
  - _What:_ Enable kubelet server certificate rotation on controller-manager.
  - _Fix:_ Edit the Controller Manager pod specification file `/etc/kubernetes/manifests/kube-controller-manager.yaml` on the Control Plane node and set the `--feature-gates` parameter to include `RotateKubeletServerCertificate=true`. ``` --feature-gates=RotateKubeletServerCertificate=true ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0149-ensurethatthecontrollermanagerrotatekubeletservercertificateargumentissettotrue.json)
- `kubescape` **C-0174** · MEDIUM · CIS cis-aks-t1.2.0:3.2.3; cis-aks-t1.8.0:3.2.3; cis-eks-t1.7.0:3.2.3; cis-eks-t1.8.0:3.2.3; cis-v1.10.0:4.2.3; cis-v1.12.0:4.2.3 — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ Enable Kubelet authentication using certificates.
  - _Fix:_ If using a Kubelet config file, edit the file to set `authentication: x509: clientCAFile` to the location of the client CA file. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and set the below parameter in `KUBELET_AUTHZ_ARGS` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0174-ensurethattheclientcafileargumentissetasappropriate.json)
- `kubescape` **C-0182** · MEDIUM · CIS cis-aks-t1.2.0:3.2.10; cis-aks-t1.8.0:3.2.10; cis-v1.10.0:4.2.10; cis-v1.12.0:4.2.10 — Ensure that the --rotate-certificates argument is not set to false
  - _What:_ Enable kubelet client certificate rotation.
  - _Fix:_ If using a Kubelet config file, edit the file to add the line `rotateCertificates: true` or remove it altogether to use the default value. If using command line arguments, edit the kubelet service file `/etc/kubernetes/kubelet.conf` on each worker node and remove `--rotate-certificates=false` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0182-ensurethattherotatecertificatesargumentisnotsettofalse.json)
- `kubescape` **C-0183** · MEDIUM · CIS cis-aks-t1.2.0:3.2.11; cis-aks-t1.8.0:3.2.11; cis-eks-t1.7.0:3.2.9; cis-eks-t1.8.0:3.2.9; cis-v1.10.0:4.2.11; cis-v1.12.0:4.2.11 — Verify that the RotateKubeletServerCertificate argument is set to true
  - _What:_ Enable kubelet server certificate rotation.
  - _Fix:_ The `RotateKubeletServerCertificate` feature gate is enabled by default, so no action is needed unless it has been explicitly disabled. If it has, edit the kubelet config file specified by `--config` and remove `RotateKubeletServerCertificate: false` from `featureGates`, or edit the kubelet …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0183-verifythattherotatekubeletservercertificateargumentissettotrue.json)
- `kubescape` **C-0184** · MEDIUM · CIS cis-v1.10.0:4.2.12; cis-v1.12.0:4.2.12 — Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
  - _What:_ Ensure that the Kubelet is configured to only use strong cryptographic ciphers.
  - _Fix:_ If using a Kubelet config file, edit the file to set `TLSCipherSuites:` to …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0184-ensurethatthekubeletonlymakesuseofstrongcryptographicciphers.json)
- `prowler` **controllermanager_rotate_kubelet_server_cert** · MEDIUM — Controller Manager pod has RotateKubeletServerCertificate set to true
  - _What:_ **Kubernetes controller manager** configuration includes the `RotateKubeletServerCertificate=true` feature gate for automatic rotation of **kubelet server certificates**
  - _Fix:_ Enable `RotateKubeletServerCertificate=true` on the controller manager and ensure kubelets participate in rotation. Use short-lived certs, automated renewal, and strict TLS validation to maintain **availability**, protect **integrity**, and uphold **cryptographic hygiene**. Avoid insecure …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/controllermanager/controllermanager_rotate_kubelet_server_cert/controllermanager_rotate_kubelet_server_cert.metadata.json)
- `prowler` **kubelet_strong_ciphers_only** · MEDIUM — Kubelet uses only strong TLS cipher suites
  - _What:_ **Kubernetes Kubelet HTTPS** configuration is assessed for use of **strong TLS cipher suites**. The presence of `tlsCipherSuites` is checked and its values are validated against an approved, modern allowlist (e.g., ECDHE with GCM/CHACHA20).
  - _Fix:_ Restrict `tlsCipherSuites` to a minimal set of modern suites (ECDHE with GCM or CHACHA20) and prefer `TLS1.2+`/`TLS1.3`. Remove deprecated CBC/RC4/3DES suites. Apply **defense in depth**: limit network access to the kubelet, rotate certificates, and review cipher policy regularly for deprecations. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_strong_ciphers_only/kubelet_strong_ciphers_only.metadata.json)
- `trivy` **KCV-0004** · LOW — Ensure that the --kubelet-https argument is set to true
  - _What:_ [API server] Use https for kubelet connections.
  - _Fix:_ Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and remove the --kubelet-https parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubelet_https.rego)
- `trivy` **KCV-0005** · LOW — Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - _What:_ [API server] Enable certificate based kubelet authentication.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubelet_client_certificate_and_key.rego)
- `trivy` **KCV-0006** · LOW — Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - _What:_ [API server] Verify kubelet's certificate before establishing connection.
  - _Fix:_ Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_kubelet_certificate_authority.rego)
- `trivy` **KCV-0038** · LOW — Ensure that the RotateKubeletServerCertificate argument is set to true
  - _What:_ [controller manager] Enable kubelet server certificate rotation on controller-manager.
  - _Fix:_ Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true .
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/controllermanager_rotate_kubelet_server_certificate.rego)
- `checkov` **CKV_K8S_112** · CIS cis-1.6:4.2.12 — Ensure that the RotateKubeletServerCertificate argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RotateKubeletServerCertificate.py)
- `checkov` **CKV_K8S_140** · CIS cis-1.6:4.2.3 — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ [kubelet] Ensure that the --client-ca-file argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletClientCa.py)
- `checkov` **CKV_K8S_148** · CIS cis-1.6:4.2.10 — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ [kubelet] Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletKeyFilesSetAppropriate.py)
- `checkov` **CKV_K8S_149** · CIS cis-1.6:4.2.11 — Ensure that the --rotate-certificates argument is not set to false
  - _What:_ [kubelet] Ensure that the --rotate-certificates argument is not set to false
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubletRotateCertificates.py)
- `checkov` **CKV_K8S_151** · CIS cis-1.6:4.2.13 — Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/KubeletCryptographicCiphers.py)
- `checkov` **CKV_K8S_71** — Ensure that the --kubelet-https argument is set to true
  - _What:_ [API server] Ensure that the --kubelet-https argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerKubeletHttps.py)
- `checkov` **CKV_K8S_72** — Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - _What:_ [API server] Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerKubeletClientCertAndKey.py)
- `checkov` **CKV_K8S_73** — Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - _What:_ [API server] Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerkubeletCertificateAuthority.py)
- `kube-bench` **1.2.4** · CIS cis-1.11:1.2.4 — Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - _What:_ [API Server] Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets. Then, edit API server pod specification file $apiserverconf on the control plane node and set the kubelet client certificate and key parameters as below. …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.2.5** · CIS cis-1.11:1.2.5 — Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - _What:_ [API Server] Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the --kubelet-certificate-authority parameter to the path to the cert file for the certificate …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **1.3.6** · CIS cis-1.11:1.3.6 — Ensure that the RotateKubeletServerCertificate argument is set to true
  - _What:_ [Controller Manager] Ensure that the RotateKubeletServerCertificate argument is set to true
  - _Fix:_ Edit the Controller Manager pod specification file $controllermanagerconf on the control plane node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true. --feature-gates=RotateKubeletServerCertificate=true
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)
- `kube-bench` **4.2.10** · CIS cis-1.11:4.2.10 — Ensure that the --rotate-certificates argument is not set to false
  - _What:_ [Kubelet] Ensure that the --rotate-certificates argument is not set to false
  - _Fix:_ If using a Kubelet config file, edit the file to add the line `rotateCertificates` to `true` or remove it altogether to use the default value. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and remove --rotate-certificates=false argument from the …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.11** · manual · CIS cis-1.11:4.2.11 — Verify that the RotateKubeletServerCertificate argument is set to true
  - _What:_ [Kubelet] Verify that the RotateKubeletServerCertificate argument is set to true
  - _Fix:_ Edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_CERTIFICATE_ARGS variable. --feature-gates=RotateKubeletServerCertificate=true Based on your system, restart the kubelet service. For example: systemctl daemon-reload systemctl restart …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.12** · manual · CIS cis-1.11:4.2.12 — Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
  - _What:_ [Kubelet] Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers
  - _Fix:_ If using a Kubelet config file, edit the file to set `tlsCipherSuites` to …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.3** · CIS cis-1.11:4.2.3 — Ensure that the --client-ca-file argument is set as appropriate
  - _What:_ [Kubelet] Ensure that the --client-ca-file argument is set as appropriate
  - _Fix:_ If using a Kubelet config file, edit the file to set `authentication.x509.clientCAFile` to the location of the client CA file. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_AUTHZ_ARGS variable. …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.9** · manual · CIS cis-1.11:4.2.9 — Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _What:_ [Kubelet] Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate
  - _Fix:_ If using a Kubelet config file, edit the file to set `tlsCertFile` to the location of the certificate file to use to identify this Kubelet, and `tlsPrivateKeyFile` to the location of the corresponding private key file. If using command line arguments, edit the kubelet service file $kubeletsvc on …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)

### Other  
_12 rules · tools: kube-bench, kubescape, kyverno, prowler_

- `kubescape` **C-0069** · CRITICAL — Disable anonymous access to Kubelet service
  - _What:_ By default, requests to the kubelet's HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated.
  - _Fix:_ Start the kubelet with the --anonymous-auth=false flag.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0069-disableanonymousaccesstokubeletservice.json)
- `prowler` **kubelet_disable_anonymous_auth** · HIGH — Kubelet anonymous authentication is disabled
  - _What:_ **Kubernetes Kubelet** configuration for its HTTPS endpoint is evaluated to ensure **anonymous authentication** is disabled, requiring authenticated requests (`authentication.anonymous.enabled=false`).
  - _Fix:_ Disable anonymous auth and require **strong, authenticated clients** (mTLS or tokens). Delegate authorization to **RBAC** and apply **least privilege** for kubelet APIs. Limit network exposure to the kubelet endpoint and monitor access patterns as part of **defense in depth**. Steps: 1. SSH to …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_disable_anonymous_auth/kubelet_disable_anonymous_auth.metadata.json)
- `prowler` **kubelet_event_record_qps** · HIGH — Kubelet eventRecordQPS is set to a positive value
  - _What:_ **Kubernetes Kubelet** configuration defines **event rate limiting** via `eventRecordQPS`. The setting is evaluated for presence and a positive value, where `0` means unlimited event generation.
  - _Fix:_ Set `eventRecordQPS` to a positive, workload-appropriate rate and avoid `0`. Monitor event volumes and backpressure and tune periodically. Apply **defense in depth** by limiting noisy workloads and enforcing operational safeguards to prevent event storms. Steps: 1. SSH to each node running kubelet …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_event_record_qps/kubelet_event_record_qps.metadata.json)
- `kubescape` **C-0291** · MEDIUM · CIS cis-v1.12.0:4.3.1 — Ensure that the kube-proxy metrics service is bound to localhost
  - _What:_ Do not bind the kube-proxy metrics port to non-loopback addresses.
  - _Fix:_ If running kube-proxy with a configuration file, edit the kube-proxy configuration file and set the metricsBindAddress to `127.0.0.1:10249`. If running kube-proxy with command line arguments, set `--metrics-bind-address=127.0.0.1:10249`. Restart kube-proxy for changes to take effect.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0291-ensurethatthekubeproxymetricsserviceisboundtolocalhost.json)
- `prowler` **kubelet_manage_iptables** · MEDIUM — Kubelet configuration has makeIPTablesUtilChains set to true
  - _What:_ **Kubernetes Kubelet** configured with `makeIPTablesUtilChains` manages **iptables utility chains**, keeping node firewall primitives aligned with dynamic pod networking. The setting is expected to be present and enabled in kubelet configuration.
  - _Fix:_ Enable kubelet management of **iptables utility chains** by setting `makeIPTablesUtilChains=true`. Prefer **automation over manual iptables edits** to prevent drift. Combine with **network policies**, least privilege, and **defense in depth** to control east-west traffic. *If your CNI replaces …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_manage_iptables/kubelet_manage_iptables.metadata.json)
- `prowler` **kubelet_streaming_connection_timeout** · MEDIUM — Kubelet streaming connection idle timeout is not set to 0
  - _What:_ **Kubernetes Kubelet** streaming sessions use a **non-zero idle timeout** via `streamingConnectionIdleTimeout` for `exec`, `logs`, and `port-forward` connections. Assesses whether this setting exists and is not `0`.
  - _Fix:_ Set a bounded, non-zero `streamingConnectionIdleTimeout` aligned to operational needs; avoid `0`. Apply consistently across nodes, prefer fail-safe defaults, and monitor for unusually long streaming sessions. This supports **defense in depth** and preserves node **availability**. Steps: 1. SSH to …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/kubelet/kubelet_streaming_connection_timeout/kubelet_streaming_connection_timeout.metadata.json)
- `kubescape` **C-0284** · LOW · CIS cis-v1.10.0:4.2.13; cis-v1.12.0:4.2.13 — Ensure that the Kubelet is configured to limit pod PIDS
  - _What:_ Ensure that the Kubelet sets limits on the number of PIDs that can be created by pods running on the node.
  - _Fix:_ Decide on an appropriate level for this parameter and set it, either via the `--pod-max-pids` command line parameter or the `PodPidsLimit` configuration file setting.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0284-ensurethatthekubeletconfiguredtolimitpodpids.json)
- `kube-bench` **4.2.13** · manual · CIS cis-1.11:4.2.13 — Ensure that a limit is set on pod PIDs
  - _What:_ [Kubelet] Ensure that a limit is set on pod PIDs
  - _Fix:_ Decide on an appropriate level for this parameter and set it, either via the --pod-max-pids command line parameter or the PodPidsLimit configuration file setting.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.15** · manual · CIS cis-1.11:4.2.15 — Ensure that the --IPAddressDeny is set to any
  - _What:_ [Kubelet] Ensure that the --IPAddressDeny is set to any
  - _Fix:_ Configuring the setting IPAddressDeny=any will deny service to any IP address not specified in the complimentary setting IPAddressAllow configuration parameter ( IPAddressDeny=any IPAddressAllow={{ kubelet_secure_addresses }} *Note kubelet_secure_addresses: "localhost link-local {{ …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.2.8** · manual · CIS cis-1.11:4.2.8 — Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture
  - _What:_ [Kubelet] Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture
  - _Fix:_ If using a Kubelet config file, edit the file to set `eventRecordQPS` to an appropriate level. If using command line arguments, edit the kubelet service file $kubeletsvc on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. Based on your system, restart the kubelet …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kube-bench` **4.3.1** · CIS cis-1.11:4.3.1 — Ensure that the kube-proxy metrics service is bound to localhost
  - _What:_ [kube-proxy] Ensure that the kube-proxy metrics service is bound to localhost
  - _Fix:_ Modify or remove any values which bind the metrics service to a non-localhost address. The default value is 127.0.0.1:10249.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/node.yaml)
- `kyverno` **restrict-controlplane-scheduling** — Restrict control plane scheduling
  - _What:_ Scheduling non-system Pods to control plane nodes (which run kubelet) is often undesirable because it takes away resources from the control plane components and can represent a possible security threat vector. This policy prevents users from setting a toleration in a Pod spec which allows running on control plane nodes with the taint key `node-role.kubernetes.io/master`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-controlplane-scheduling/restrict-controlplane-scheduling.yaml)


## Workload security (Pod Security)

### Allowed / trusted registries  
_1 rules · tools: kubescape_

- `kubescape` **C-0297** · HIGH — Agent Sandbox hardened runtime class
  - _What:_ Ensure Sandbox and SandboxTemplate resources use an approved hardened runtimeClassName to isolate untrusted workloads from the host kernel.
  - _Fix:_ Set spec.podTemplate.spec.runtimeClassName on the Sandbox or SandboxTemplate to an approved hardened runtime.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0297-hardenedsandboxruntimeclass.json)

### AppArmor  
_2 rules · tools: gatekeeper, trivy_

- `trivy` **KSV-0002** · LOW — Runtime/Default AppArmor profile not set
  - _What:_ According to pod security standard 'AppArmor', the AppArmor key must be set to the runtime/default profile or to be undefined.
  - _Fix:_ set the 'runtime/default' value from 'container.apparmor.security.beta.kubernetes.io'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apparmor_policy_disabled.rego)
- `gatekeeper` **k8spspapparmor** — App Armor
  - _What:_ Configures an allow-list of AppArmor profiles for use by containers. This corresponds to specific annotations applied to a PodSecurityPolicy. For information on AppArmor, see https://kubernetes.io/docs/tutorials/clusters/apparmor/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/apparmor/template.yaml)

### CPU/memory limits & requests  
_2 rules · tools: kubescape_

- `kubescape` **C-0303** · HIGH — Agent Sandbox resource ceilings
  - _What:_ Ensure Agent Sandbox SandboxTemplate containers have CPU and memory resource limits set and that they do not exceed configured ceilings. Unrestricted agent containers may consume excessive resources and negatively affect other workloads sharing the node.
  - _Fix:_ Set spec.podTemplate.spec.containers[].resources.limits.cpu and memory on the SandboxTemplate to values within the configured ceilings.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0303-agentsandboxresourceceilings.json)
- `kubescape` **C-0311** · HIGH — Agent Sandbox container resource limits
  - _What:_ Every regular and init container in an Agent Sandbox embedded PodSpec should declare CPU and memory limits.
  - _Fix:_ Set resources.limits.cpu and resources.limits.memory on every container and init container under spec.podTemplate.spec.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0311-agent-sandbox-container-limits.json)

### Container runtime socket mount  
_2 rules · tools: kube-linter, kyverno_

- `kyverno` **docker-socket-check** · MEDIUM — Docker Socket Requires Label
  - _What:_ Accessing a container engine's socket is for highly specialized use cases and should generally be disabled. If access must be granted, it should be done on an explicit basis. This policy requires that, for any Pod mounting the Docker socket, it must have the label `allow-docker` set to `true`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/docker-socket-requires-label/docker-socket-requires-label.yaml)
- `kube-linter` **docker-sock** — Docker sock
  - _What:_ Alert on deployments with docker.sock mounted in containers.
  - _Fix:_ Ensure the Docker socket is not mounted inside any containers by removing the associated Volume and VolumeMount in deployment yaml specification. If the Docker socket is mounted inside a container it could allow processes running within the container to execute Docker commands which would …
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/docker-sock.yaml)

### File permissions / ownership  
_2 rules · tools: checkov, kubescape_

- `kubescape` **C-0035** · MEDIUM — Administrative Roles
  - _What:_ Attackers who have cluster admin permissions (can perform any action on any resource), can take advantage of their privileges for malicious activities. This control determines which subjects have cluster admin permissions.
  - _Fix:_ You should apply least privilege principle. Make sure cluster admin permissions are granted only when it is absolutely necessary. Don't use subjects with such high permissions for daily operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0035-clusteradminbinding.json)
- `checkov` **CKV2_K8S_2** — Granting `create` permissions to `nodes/proxy` or `pods/exec` sub resources allows potential privilege escalation
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/graph_checks/NoCreateNodesProxyOrPodsExec.yaml)

### Host IPC namespace  
_10 rules · tools: checkov, kube-bench, kube-linter, kubescape, polaris, prowler, trivy_

- `polaris` **hostIPCSet** · HIGH — Host IPC should not be configured
  - _What:_ Pass: Host IPC is not configured | Fail: Host IPC should not be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostIPCSet.yaml)
- `prowler` **core_minimize_hostIPC_containers** · HIGH — Pod does not use the host IPC namespace
  - _What:_ **Kubernetes pods** are evaluated for use of the host's IPC namespace via the `hostIPC` setting. Workloads declaring `hostIPC: true` share node IPC resources (shared memory, semaphores, message queues) instead of isolated container IPC.
  - _Fix:_ Disallow `hostIPC` with **Pod Security Admission** enforcing **Pod Security Standards** (Baseline/Restricted) or equivalent policy engines. Apply **least privilege** and defense in depth: keep IPC namespaces isolated, grant tightly scoped exceptions only, and prefer app-level messaging or Services …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_hostIPC_containers/core_minimize_hostIPC_containers.metadata.json)
- `trivy` **KSV-0008** · HIGH — Access to host IPC namespace
  - _What:_ Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.
  - _Fix:_ Do not set 'spec.template.spec.hostIPC' to true.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/host_ipc.rego)
- `kubescape` **C-0195** · MEDIUM · CIS cis-eks-t1.7.0:4.2.3; cis-eks-t1.8.0:4.2.3 — Minimize the admission of containers wishing to share the host IPC namespace
  - _What:_ Do not generally permit containers to be run with the `hostIPC` flag set to true.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostIPC` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0195-minimizetheadmissionofcontainerswishingtosharethehostipcnamespace.json)
- `kubescape` **C-0215** · MEDIUM · CIS cis-aks-t1.2.0:4.2.3; cis-aks-t1.8.0:4.2.3 — Minimize the admission of containers wishing to share the host IPC namespace
  - _What:_ Do not generally permit containers to be run with the `hostIPC` flag set to true.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.hostIPC` field is omitted or set to false.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0215-minimizetheadmissionofcontainerswishingtosharethehostipcnamespace.json)
- `kubescape` **C-0276** · MEDIUM · CIS cis-v1.10.0:5.2.4; cis-v1.12.0:5.2.4 — Minimize the admission of containers wishing to share the host IPC namespace
  - _What:_ Do not generally permit containers to be run with the hostIPC flag set to true.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostIPC` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0276-minimizetheadmissionofcontainerswishingtosharethehostipcnamespace.json)
- `checkov` **CKV_K8S_18** · CIS cis-1.3:1.7.3; cis-1.5:5.2.3 — Containers should not share the host IPC namespace
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ShareHostIPC.py)
- `checkov` **CKV_K8S_3** · CIS cis-1.3:1.7.3; cis-1.5:5.2.3 — Do not admit containers wishing to share the host IPC namespace
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ShareHostIPCPSP.py)
- `kube-bench` **5.2.4** · manual · CIS cis-1.11:5.2.4 — Minimize the admission of containers wishing to share the host IPC namespace
  - _What:_ [Pod Security Standards] Minimize the admission of containers wishing to share the host IPC namespace
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostIPC` containers. Audit: the audit retrieves each Pod' spec.IPC. Condition: is_compliant is false if Pod's spec.hostIPC is set to `true`. Default: by default, there are no restrictions on the …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **host-ipc** — Host ipc
  - _What:_ Alert on pods/deployment-likes with sharing host's IPC namespace
  - _Fix:_ Ensure the host's IPC namespace is not shared.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/hostipc.yaml)

### Host PID namespace  
_9 rules · tools: gatekeeper, kube-linter, kubescape, polaris, prowler, trivy_

- `kubescape` **C-0038** · HIGH — Host PID/IPC privileges
  - _What:_ Containers should be isolated from the host machine as much as possible. The hostPID and hostIPC fields in deployment yaml may allow cross-container influence and may expose the host itself to potentially malicious or destructive actions. This control identifies all pods using hostPID or hostIPC privileges.
  - _Fix:_ Remove hostPID and hostIPC from the yaml file(s) privileges unless they are absolutely necessary.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0038-hostpidipcprivileges.json)
- `polaris` **hostPIDSet** · HIGH — Host PID should not be configured
  - _What:_ Pass: Host PID is not configured | Fail: Host PID should not be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostPIDSet.yaml)
- `prowler` **core_minimize_hostPID_containers** · HIGH — Pod does not use the host PID namespace
  - _What:_ **Kubernetes Pods** configured with `hostPID: true` are identified, indicating the container shares the node's **host PID namespace**.
  - _Fix:_ Disallow `hostPID` for application Pods via **admission policies** aligned to **Pod Security Standards (Baseline/Restricted)**. Allow only for tightly controlled system workloads. Apply **least privilege**, isolate such Pods on dedicated nodes, and favor debug/observability methods that avoid host …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_hostPID_containers/core_minimize_hostPID_containers.metadata.json)
- `trivy` **KSV-0010** · HIGH — Access to host PID
  - _What:_ Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.
  - _Fix:_ Do not set 'spec.template.spec.hostPID' to true.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/host_pid.rego)
- `kubescape` **C-0194** · MEDIUM · CIS cis-eks-t1.7.0:4.2.2; cis-eks-t1.8.0:4.2.2 — Minimize the admission of containers wishing to share the host process ID namespace
  - _What:_ Do not generally permit containers to be run with the `hostPID` flag set to true.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostPID` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0194-minimizetheadmissionofcontainerswishingtosharethehostprocessidnamespace.json)
- `kubescape` **C-0214** · MEDIUM · CIS cis-aks-t1.2.0:4.2.2; cis-aks-t1.8.0:4.2.2 — Minimize the admission of containers wishing to share the host process ID namespace
  - _What:_ Do not generally permit containers to be run with the `hostPID` flag set to true.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.hostPID` field is omitted or set to false.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0214-minimizetheadmissionofcontainerswishingtosharethehostprocessidnamespace.json)
- `kubescape` **C-0275** · MEDIUM · CIS cis-v1.10.0:5.2.3; cis-v1.12.0:5.2.3 — Minimize the admission of containers wishing to share the host process ID namespace
  - _What:_ Do not generally permit containers to be run with the hostPID flag set to true.
  - _Fix:_ Configure the Admission Controller to restrict the admission of `hostPID` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0275-minimizetheadmissionofcontainerswishingtosharethehostprocessidnamespace.json)
- `gatekeeper` **k8spsphostnamespace** — Host Namespace
  - _What:_ Disallows sharing of host PID and IPC namespaces by pod containers. Corresponds to the `hostPID` and `hostIPC` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/host-namespaces/template.yaml)
- `kube-linter` **host-pid** — Host pid
  - _What:_ Alert on pods/deployment-likes with sharing host's process namespace
  - _Fix:_ Ensure the host's process namespace is not shared.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/hostpid.yaml)

### Host network  
_9 rules · tools: checkov, kube-bench, kube-linter, kubescape, polaris, prowler, trivy_

- `polaris` **hostNetworkSet** · HIGH — Host network should not be configured
  - _What:_ Pass: Host network is not configured | Fail: Host network should not be configured
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostNetworkSet.yaml)
- `prowler` **core_minimize_hostNetwork_containers** · HIGH — Pod does not use hostNetwork
  - _What:_ **Kubernetes Pods** configured with `hostNetwork: true` are identified, meaning they share the node's network namespace and use the host's IP stack, interfaces, and ports.
  - _Fix:_ Disallow `hostNetwork` by default. Enforce **least privilege** with admission policies that block it, allowing narrowly scoped exceptions only for trusted system workloads. Prefer standard pod networking with **NetworkPolicies**, and isolate node services for **defense in depth**. Steps: 1. Open …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_hostNetwork_containers/core_minimize_hostNetwork_containers.metadata.json)
- `trivy` **KSV-0009** · HIGH — Access to host network
  - _What:_ Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.
  - _Fix:_ Do not set 'spec.template.spec.hostNetwork' to true.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/host_network.rego)
- `kubescape` **C-0196** · MEDIUM · CIS cis-eks-t1.7.0:4.2.4; cis-eks-t1.8.0:4.2.4 — Minimize the admission of containers wishing to share the host network namespace
  - _What:_ Do not generally permit containers to be run with the `hostNetwork` flag set to true.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostNetwork` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0196-minimizetheadmissionofcontainerswishingtosharethehostnetworknamespace.json)
- `kubescape` **C-0216** · MEDIUM · CIS cis-aks-t1.2.0:4.2.4; cis-aks-t1.8.0:4.2.4 — Minimize the admission of containers wishing to share the host network namespace
  - _What:_ Do not generally permit containers to be run with the `hostNetwork` flag set to true.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.hostNetwork` field is omitted or set to false.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0216-minimizetheadmissionofcontainerswishingtosharethehostnetworknamespace.json)
- `checkov` **CKV_K8S_19** · CIS cis-1.3:1.7.4; cis-1.5:5.2.4 — Containers should not share the host network namespace
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/SharedHostNetworkNamespace.py)
- `checkov` **CKV_K8S_4** · CIS cis-1.3:1.7.4; cis-1.5:5.2.4 — Do not admit containers wishing to share the host network namespace
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/SharedHostNetworkNamespacePSP.py)
- `kube-bench` **5.2.5** · manual · CIS cis-1.11:5.2.5 — Minimize the admission of containers wishing to share the host network namespace
  - _What:_ [Pod Security Standards] Minimize the admission of containers wishing to share the host network namespace
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostNetwork` containers. Audit: the audit retrieves each Pod' spec.hostNetwork. Condition: is_compliant is false if Pod's spec.hostNetwork is set to `true`. Default: by default, there are no …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **host-network** — Host network
  - _What:_ Alert on pods/deployment-likes with sharing host's network namespace
  - _Fix:_ Ensure the host's network namespace is not shared.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/hostnetwork.yaml)

### Image tag / digest pinning  
_2 rules · tools: kubescape, trivy_

- `trivy` **KSV-0014** · HIGH — Root file system is not read-only
  - _What:_ An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.
  - _Fix:_ Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/file_system_not_read_only.rego)
- `kubescape` **C-0017** · LOW — Immutable container filesystem
  - _What:_ Mutable container filesystem can be abused to inject malicious code or data into containers. Use immutable (read-only) filesystem to limit potential attacks.
  - _Fix:_ Set the filesystem of the container to read-only when possible (pod securityContext, readOnlyRootFilesystem: true). If containers application needs to write into the filesystem, it is recommended to mount secondary filesystems for specific directories where application require write access.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0017-immutablecontainerfilesystem.json)

### Legacy / risky components (Tiller, dashboard, SSH)  
_2 rules · tools: kube-linter, kubescape_

- `kubescape` **C-0042** · LOW — SSH server running inside container
  - _What:_ An SSH server that is running inside a container may be used by attackers to get remote access to the container. This control checks if pods have an open SSH port (22/2222).
  - _Fix:_ Remove SSH from the container image or limit the access to the SSH server using network policies.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0042-sshserverrunninginsidecontainer.json)
- `kube-linter` **ssh-port** — Ssh port
  - _What:_ Indicates when deployments expose port 22, which is commonly reserved for SSH access.
  - _Fix:_ Ensure that non-SSH services are not using port 22. Confirm that any actual SSH servers have been vetted.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/ssh-port.yaml)

### Linux capabilities  
_36 rules · tools: checkov, gatekeeper, kube-bench, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0046** · HIGH — Insecure capabilities
  - _What:_ Giving insecure or excessive capabilities to a container can increase the impact of the container compromise. This control identifies all the pods with dangerous capabilities (see documentation pages for details).
  - _Fix:_ Remove all insecure capabilities which are not necessary for the container.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0046-insecurecapabilities.json)
- `polaris` **dangerousCapabilities** · HIGH — Container should not have dangerous capabilities
  - _What:_ Pass: Container does not have any dangerous capabilities | Fail: Container should not have dangerous capabilities
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/dangerousCapabilities.yaml)
- `prowler` **core_minimize_containers_added_capabilities** · HIGH — Pod has no containers with added capabilities
  - _What:_ Kubernetes Pods and containers are evaluated for **added Linux capabilities** via `capabilities.add` in their security context; presence of added entries indicates elevated privileges beyond defaults.
  - _Fix:_ Apply **least privilege**: require containers to `drop: ALL` and avoid `capabilities.add` except when strictly justified (e.g., `NET_BIND_SERVICE`). Enforce with **admission policies** and separation of duties. Combine with **seccomp/AppArmor** and non-root execution for **defense in depth**. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_containers_added_capabilities/core_minimize_containers_added_capabilities.metadata.json)
- `prowler` **core_minimize_containers_capabilities_assigned** · HIGH — Pod containers have no added Linux capabilities and include capability drops when capabilities are defined
  - _What:_ **Kubernetes Pods** are inspected for container **Linux capabilities**. A finding occurs when any container sets capabilities in `add` or does not fully `drop` them (e.g., missing `ALL`), indicating capabilities are assigned instead of removed.
  - _Fix:_ Apply **least privilege**: drop `ALL` capabilities and avoid using `add`. Only reintroduce a minimal capability when absolutely required, and isolate such pods via defense-in-depth: strict RBAC, `seccomp` RuntimeDefault, AppArmor, network policies, dedicated namespaces/nodes, and admission …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_containers_capabilities_assigned/core_minimize_containers_capabilities_assigned.metadata.json)
- `prowler` **core_minimize_net_raw_capability_admission** · HIGH — Pod containers do not have the NET_RAW capability
  - _What:_ **Kubernetes pods** where any container's security context adds the `NET_RAW` Linux capability are identified. The inspection evaluates container `securityContext.capabilities.add` entries to detect explicit requests for `NET_RAW`.
  - _Fix:_ Apply **least privilege**: avoid adding `NET_RAW` and drop unnecessary Linux capabilities by default. Use cluster-wide **admission policies** to block requests for `NET_RAW`. When strictly required, isolate the workload, restrict egress with network controls, and audit capability use as part of …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_net_raw_capability_admission/core_minimize_net_raw_capability_admission.metadata.json)
- `trivy` **KSV-0005** · HIGH — SYS_ADMIN capability added
  - _What:_ SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.
  - _Fix:_ Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/SYS_ADMIN_capability.rego)
- `trivy` **KSV-0119** · HIGH — NET_RAW capability added
  - _What:_ The NET_RAW capability grants attackers the ability to eavesdrop on network traffic or generate IP traffic with falsified source addresses, posing serious security risks.
  - _Fix:_ To mitigate potential security risks, it is strongly recommended to remove the NET_RAW capability from 'containers[].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/net_raw_capability.rego)
- `trivy` **KSV-0120** · HIGH — SYS_MODULE capability added
  - _What:_ The SYS_MODULE capability grants attackers the ability to install and remove kernel modules, posing serious security risks.
  - _Fix:_ To mitigate potential security risks, it is strongly recommended to remove the SYS_MODULE capability from 'containers[].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/SYS_MODULE_capability.rego)
- `kubescape` **C-0007** · MEDIUM — Roles with delete capabilities
  - _What:_ Attackers may attempt to destroy data and resources in the cluster. This includes deleting deployments, configurations, storage, and compute resources. This control identifies all subjects that can delete resources.
  - _Fix:_ You should follow the least privilege principle and minimize the number of subjects that can delete resources.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0007-datadestruction.json)
- `kubescape` **C-0199** · MEDIUM · CIS cis-v1.10.0:5.2.8; cis-v1.12.0:5.2.8 — Minimize the admission of containers with the NET_RAW capability
  - _What:_ Do not generally permit containers with the potentially dangerous NET\_RAW capability.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with the `NET_RAW` capability.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0199-minimizetheadmissionofcontainerswiththenet_rawcapability.json)
- `kubescape` **C-0200** · MEDIUM · CIS cis-v1.10.0:5.2.9 — Minimize the admission of containers with added capabilities
  - _What:_ Do not generally permit containers with capabilities assigned beyond the default set.
  - _Fix:_ Ensure that `allowedCapabilities` is not present in policies for the cluster unless it is set to an empty array.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0200-minimizetheadmissionofcontainerswithaddedcapabilities.json)
- `kubescape` **C-0201** · MEDIUM · CIS cis-aks-t1.2.0:4.2.8; cis-aks-t1.8.0:4.2.8; cis-v1.10.0:5.2.10; cis-v1.12.0:5.2.9 — Minimize the admission of containers with capabilities assigned
  - _What:_ Do not generally permit containers with capabilities
  - _Fix:_ Review the use of capabilites in applications runnning on your cluster. Where a namespace contains applicaions which do not require any Linux capabities to operate consider adding a policy which forbids the admission of containers which do not drop all capabilities.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0201-minimizetheadmissionofcontainerswithcapabilitiesassigned.json)
- `kubescape` **C-0219** · MEDIUM · CIS cis-aks-t1.2.0:4.2.7; cis-aks-t1.8.0:4.2.7 — Minimize the admission of containers with added capabilities
  - _What:_ Do not generally permit containers with capabilities assigned beyond the default set.
  - _Fix:_ Ensure that `allowedCapabilities` is not present in PSPs for the cluster unless it is set to an empty array.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0219-minimizetheadmissionofcontainerswithaddedcapabilities.json)
- `kubescape` **C-0220** · MEDIUM — Minimize the admission of containers with capabilities assigned
  - _What:_ Do not generally permit containers with capabilities
  - _Fix:_ Review the use of capabilities in applications running on your cluster. Where a namespace contains applications which do not require any Linux capabilities to operate consider adding a PSP which forbids the admission of containers which do not drop all capabilities.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0220-minimizetheadmissionofcontainerswithcapabilitiesassigned.json)
- `kyverno` **disallow-capabilities** · MEDIUM — Disallow Capabilities
  - _What:_ Adding capabilities beyond those listed in the policy must be disallowed.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-capabilities/disallow-capabilities.yaml)
- `kyverno` **disallow-capabilities-strict** · MEDIUM — Disallow Capabilities (Strict)
  - _What:_ Adding capabilities other than `NET_BIND_SERVICE` is disallowed. In addition, all containers must explicitly drop `ALL` capabilities.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/disallow-capabilities-strict/disallow-capabilities-strict.yaml)
- `kyverno` **drop-all-capabilities** · MEDIUM — Drop All Capabilities in VPOL
  - _What:_ Capabilities permit privileged actions without giving full root access. All capabilities should be dropped from a Pod, with only those required added back. This policy ensures that all containers explicitly specify the `drop: ["ALL"]` ability. Note that this policy also illustrates how to cover drop entries in any case although this may not strictly conform to the Pod Security Standards.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-drop-all/require-drop-all.yaml)
- `kyverno` **require-labels** · MEDIUM — Require Labels
  - _What:_ Enforce the presence of required labels that identify semantic attributes of applications or Deployments. Specifically, ensure that the standard label `app.kubernetes.io/name` is present on Pods with a non-empty value to enable consistent tooling and querying capabilities.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/best-practices-vpol/require-labels/require-labels.yaml)
- `polaris` **insecureCapabilities** · MEDIUM — Container should not have insecure capabilities
  - _What:_ Pass: Container does not have any insecure capabilities | Fail: Container should not have insecure capabilities
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/insecureCapabilities.yaml)
- `polaris` **linuxHardening** · MEDIUM — Use one of AppArmor, Seccomp, SELinux, or dropping Linux Capabilities to restrict containers using unwanted privileges
  - _What:_ Pass: One of AppArmor, Seccomp, SELinux, or dropping Linux Capabilities are used to restrict containers using unwanted privileges | Fail: Use one of AppArmor, Seccomp, SELinux, or dropping Linux Capabilities to restrict containers using unwanted privileges
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/linuxHardening.yaml)
- `trivy` **KSV-0022** · MEDIUM — Specific capabilities added
  - _What:_ According to pod security standard 'Capabilities', capabilities beyond the default set must not be added.
  - _Fix:_ Do not set spec.containers[*].securityContext.capabilities.add and spec.initContainers[*].securityContext.capabilities.add.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/specific_capabilities_added.rego)
- `trivy` **KSV-0003** · LOW — Default capabilities: some containers do not drop all
  - _What:_ The container should drop all default capabilities and add only those that are needed for its execution.
  - _Fix:_ Add 'ALL' to containers[].securityContext.capabilities.drop.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/capabilities_no_drop_all.rego)
- `trivy` **KSV-0004** · LOW — Default capabilities: some containers do not drop any
  - _What:_ Security best practices require containers to run with minimal required capabilities.
  - _Fix:_ Specify at least one unneeded capability in 'containers[].securityContext.capabilities.drop'
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/capabilities_no_drop_at_least_one.rego)
- `trivy` **KSV-0106** · LOW — Container capabilities must only include NET_BIND_SERVICE
  - _What:_ Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.
  - _Fix:_ Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers[*].securityContext.capabilities.add'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/drop_all_capabilities_only_add_net_bind_service.rego)
- `checkov` **CKV_K8S_24** · CIS cis-1.5:5.2.8 — Do not allow containers with added capability
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/AllowedCapabilitiesPSP.py)
- `checkov` **CKV_K8S_25** · CIS cis-1.5:5.2.8 — Minimize the admission of containers with added capability
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/AllowedCapabilities.py)
- `checkov` **CKV_K8S_28** · CIS cis-1.3:1.7.7; cis-1.5:5.2.7 — Minimize the admission of containers with the NET_RAW capability
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DropCapabilities.py)
- `checkov` **CKV_K8S_36** · CIS cis-1.5:5.2.9 — Minimize the admission of containers with capabilities assigned
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/MinimizeCapabilitiesPSP.py)
- `checkov` **CKV_K8S_37** · CIS cis-1.5:5.2.9 — Minimize the admission of containers with capabilities assigned
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/MinimizeCapabilities.py)
- `checkov` **CKV_K8S_39** — Do not use the CAP_SYS_ADMIN linux capability
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/AllowedCapabilitiesSysAdmin.py)
- `checkov` **CKV_K8S_7** · CIS cis-1.3:1.7.7; cis-1.5:5.2.7 — Do not admit containers with the NET_RAW capability
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DropCapabilitiesPSP.py)
- `gatekeeper` **k8spspcapabilities** — Capabilities
  - _What:_ Controls Linux capabilities on containers. Corresponds to the `allowedCapabilities` and `requiredDropCapabilities` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/capabilities/template.yaml)
- `kube-bench` **5.2.10** · manual · CIS cis-1.11:5.2.10 — Minimize the admission of containers with capabilities assigned
  - _What:_ [Pod Security Standards] Minimize the admission of containers with capabilities assigned
  - _Fix:_ Review the use of capabilites in applications running on your cluster. Where a namespace contains applications which do not require any Linux capabities to operate consider adding a PSP which forbids the admission of containers which do not drop all capabilities.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.2.8** · manual · CIS cis-1.11:5.2.8 — Minimize the admission of containers with the NET_RAW capability
  - _What:_ [Pod Security Standards] Minimize the admission of containers with the NET_RAW capability
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with the `NET_RAW` capability.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.2.9** · manual · CIS cis-1.11:5.2.9 — Minimize the admission of containers with added capabilities
  - _What:_ [Pod Security Standards] Minimize the admission of containers with added capabilities
  - _Fix:_ Ensure that `allowedCapabilities` is not present in policies for the cluster unless it is set to an empty array. Audit: the audit retrieves each Pod's container(s) added capabilities. Condition: is_compliant is false if added capabilities are added for a given container. Default: Containers run …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **drop-net-raw-capability** — Drop net raw capability
  - _What:_ Indicates when containers do not drop NET_RAW capability
  - _Fix:_ NET_RAW makes it so that an application within the container is able to craft raw packets, use raw sockets, and bind to any address. Remove this capability in the containers under containers security contexts.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/drop-net-raw-capability.yaml)

### Liveness / readiness probes  
_2 rules · tools: gatekeeper, kyverno_

- `gatekeeper` **k8spsphostprobeslifecycle** — Host Probes and Lifecycle Hooks
  - _What:_ Disallows specifying the host field in probes and lifecycle hooks. The Baseline profile (v1.34+) requires that probes (livenessProbe, readinessProbe, startupProbe) and lifecycle hooks (postStart, preStop) must not specify a host field. This prevents containers from executing network requests to the host node. For more information, see …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/host-probes-lifecycle/template.yaml)
- `kyverno` **deny-commands-in-exec-probe** — Deny Commands in Exec Probe
  - _What:_ Developers may feel compelled to use simple shell commands as a workaround to creating "proper" liveness or readiness probes for a Pod. Such a practice can be discouraged via detection of those commands. This policy prevents the use of certain commands `jcmd`, `ps`, or `ls` if found in a Pod's liveness exec probe.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/deny-commands-in-exec-probe/deny-commands-in-exec-probe.yaml)

### Pod Security Standards / PSA / PSP  
_7 rules · tools: gatekeeper, kube-bench, kyverno, trivy_

- `kyverno` **disallow-host-namespaces** · MEDIUM — Disallow Host Namespaces
  - _What:_ Host namespaces (Process ID namespace, Inter-Process Communication namespace, and network namespace) allow access to shared information and can be used to elevate privileges. Pods should not be allowed access to host namespaces. This policy ensures fields which make use of these host namespaces are unset or set to `false`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-host-namespaces/disallow-host-namespaces.yaml)
- `trivy` **KSV-0028** · LOW — Non-core volume types used.
  - _What:_ According to pod security standard 'Volume types', non-core volume types must not be used.
  - _Fix:_ Do not Set 'spec.volumes[*]' to any of the disallowed volume types.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/non_core_volume_types.rego)
- `gatekeeper` **k8spspflexvolumes** — FlexVolumes
  - _What:_ Controls the allowlist of FlexVolume drivers. Corresponds to the `allowedFlexVolumes` field in PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#flexvolume-drivers
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/flexvolume-drivers/template.yaml)
- `gatekeeper` **k8spspvolumetypes** — Volume Types
  - _What:_ Restricts mountable volume types to those specified by the user. Corresponds to the `volumes` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/volumes/template.yaml)
- `kube-bench` **5.2.1** · manual · CIS cis-1.11:5.2.1 — Ensure that the cluster has at least one active policy control mechanism in place
  - _What:_ [Pod Security Standards] Ensure that the cluster has at least one active policy control mechanism in place
  - _Fix:_ Ensure that either Pod Security Admission or an external policy control system is in place for every namespace which contains user workloads.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.2.3** · manual · CIS cis-1.11:5.2.3 — Minimize the admission of containers wishing to share the host process ID namespace
  - _What:_ [Pod Security Standards] Minimize the admission of containers wishing to share the host process ID namespace
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostPID` containers. Audit: the audit retrieves each Pod' spec.hostPID. Condition: is_compliant is false if Pod's spec.hostPID is set to `true`. Default: by default, there are no restrictions on …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-bench` **5.2.7** · manual · CIS cis-1.11:5.2.7 — Minimize the admission of root containers
  - _What:_ [Pod Security Standards] Minimize the admission of root containers
  - _Fix:_ Create a policy for each namespace in the cluster, ensuring that either `MustRunAsNonRoot` or `MustRunAs` with the range of UIDs not including 0, is set.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### Privilege escalation  
_13 rules · tools: checkov, gatekeeper, kube-bench, kube-linter, kubescape, kyverno, polaris, prowler_

- `polaris` **privilegeEscalationAllowed** · HIGH — Privilege escalation should not be allowed
  - _What:_ Pass: Privilege escalation not allowed | Fail: Privilege escalation should not be allowed
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/privilegeEscalationAllowed.yaml)
- `prowler` **core_minimize_allowPrivilegeEscalation_containers** · HIGH — Pod does not allow privilege escalation in any container
  - _What:_ **Kubernetes Pods** are evaluated for containers that enable `allowPrivilegeEscalation`. The finding highlights pods where any container permits processes to gain extra privileges; pods whose containers set `allowPrivilegeEscalation: false` are noted as not allowing escalation.
  - _Fix:_ Set `allowPrivilegeEscalation: false` by default and apply **least privilege**: - run as non-root; drop caps (`drop: ["ALL"]`) - avoid `privileged`; use `readOnlyRootFilesystem` - enforce via namespace admission policies (e.g., PSA/OPA) and monitor exceptions Steps: 1. Open your Kubernetes …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_allowPrivilegeEscalation_containers/core_minimize_allowPrivilegeEscalation_containers.metadata.json)
- `kubescape` **C-0016** · MEDIUM — Allow privilege escalation
  - _What:_ Attackers may gain access to a container and uplift its privilege to enable excessive capabilities.
  - _Fix:_ If your application does not need it, make sure the allowPrivilegeEscalation field of the securityContext is set to false.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0016-allowprivilegeescalation.json)
- `kubescape` **C-0197** · MEDIUM · CIS cis-eks-t1.7.0:4.2.5; cis-eks-t1.8.0:4.2.5; cis-v1.10.0:5.2.6; cis-v1.12.0:5.2.6 — Minimize the admission of containers with allowPrivilegeEscalation
  - _What:_ Do not generally permit containers to be run with the `allowPrivilegeEscalation` flag set to true. Allowing this right can lead to a process running a container getting more rights than it started with. It's important to note that these rights are still constrained by the overall container sandbox, and this setting does not relate to the use of privileged containers.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of conatiners with `.spec.allowPrivilegeEscalation`set to `true`.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0197-minimizetheadmissionofcontainerswithallowprivilegeescalation.json)
- `kubescape` **C-0217** · MEDIUM · CIS cis-aks-t1.2.0:4.2.5; cis-aks-t1.8.0:4.2.5 — Minimize the admission of containers with allowPrivilegeEscalation
  - _What:_ Do not generally permit containers to be run with the `allowPrivilegeEscalation` flag set to true.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.allowPrivilegeEscalation` field is omitted or set to false.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0217-minimizetheadmissionofcontainerswithallowprivilegeescalation.json)
- `kubescape` **C-0278** · MEDIUM · CIS cis-eks-t1.8.0:4.1.9; cis-v1.10.0:5.1.9; cis-v1.12.0:5.1.9 — Minimize access to create persistent volumes
  - _What:_ The ability to create persistent volumes in a cluster can provide an opportunity for privilege escalation, via the creation of hostPath volumes.
  - _Fix:_ Where possible, remove `create` access to `persistentvolume` objects in the cluster.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0278-minimizeaccesstocreatepv.json)
- `kubescape` **C-0281** · MEDIUM · CIS cis-aks-t1.8.0:4.1.11; cis-eks-t1.8.0:4.1.11; cis-v1.10.0:5.1.12; cis-v1.12.0:5.1.12 — Minimize access to webhook configuration objects
  - _What:_ Users with rights to create/modify/delete validatingwebhookconfigurations or mutatingwebhookconfigurations can control webhooks that can read any object admitted to the cluster, and in the case of mutating webhooks, also mutate admitted objects. This could allow for privilege escalation or disruption of the operation of the cluster.
  - _Fix:_ Where possible, remove access to the validatingwebhookconfigurations or mutatingwebhookconfigurations objects
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0281-minimizeaccesstoadmissionwebhook.json)
- `kyverno` **disallow-privilege-escalation** · MEDIUM — Disallow Privilege Escalation
  - _What:_ Privilege escalation, such as via set-user-ID or set-group-ID file mode, should not be allowed. This policy ensures the `allowPrivilegeEscalation` field is set to `false`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/disallow-privilege-escalation/disallow-privilege-escalation.yaml)
- `checkov` **CKV_K8S_20** · CIS cis-1.3:1.7.5; cis-1.5:5.2.5 — Containers should not run with allowPrivilegeEscalation
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/AllowPrivilegeEscalation.py)
- `checkov` **CKV_K8S_5** · CIS cis-1.3:1.7.5; cis-1.5:5.2.5 — Containers should not run with allowPrivilegeEscalation
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/AllowPrivilegeEscalationPSP.py)
- `gatekeeper` **k8spspallowprivilegeescalationcontainer** — Allow Privilege Escalation in Container
  - _What:_ Controls restricting escalation to root privileges. Corresponds to the `allowPrivilegeEscalation` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/allow-privilege-escalation/template.yaml)
- `kube-bench` **5.2.6** · manual · CIS cis-1.11:5.2.6 — Minimize the admission of containers with allowPrivilegeEscalation
  - _What:_ [Pod Security Standards] Minimize the admission of containers with allowPrivilegeEscalation
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with `.securityContext.allowPrivilegeEscalation` set to `true`. Audit: the audit retrieves each Pod's container(s) `.securityContext.allowPrivilegeEscalation`. Condition: is_compliant is …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **privilege-escalation-container** — Privilege escalation container
  - _What:_ Alert on containers of allowing privilege escalation that could gain more privileges than its parent process.
  - _Fix:_ Ensure containers do not allow privilege escalation by setting allowPrivilegeEscalation=false, privileged=false and removing CAP_SYS_ADMIN capability. See https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ for more details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/privilege-escalation.yaml)

### Privileged containers  
_16 rules · tools: checkov, gatekeeper, kube-bench, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0057** · HIGH — Privileged container
  - _What:_ Potential attackers may gain access to privileged containers and inherit access to the host resources. Therefore, it is not recommended to deploy privileged containers unless it is absolutely necessary. This control identifies all the privileged Pods.
  - _Fix:_ Remove privileged capabilities by setting the securityContext.privileged to false. If you must deploy a Pod as privileged, add other restriction to it, such as network policy, Seccomp etc and still remove all unnecessary capabilities. Use the exception mechanism to remove unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0057-privilegedcontainer.json)
- `kubescape` **C-0193** · HIGH · CIS cis-eks-t1.7.0:4.2.1; cis-eks-t1.8.0:4.2.1; cis-v1.10.0:5.2.2; cis-v1.12.0:5.2.2 — Minimize the admission of privileged containers
  - _What:_ Do not generally permit containers to be run with the `securityContext.privileged` flag set to `true`.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of privileged containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0193-minimizetheadmissionofprivilegedcontainers.json)
- `polaris` **runAsPrivileged** · HIGH — Should not be running as privileged
  - _What:_ Pass: Not running as privileged | Fail: Should not be running as privileged
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/runAsPrivileged.yaml)
- `prowler` **core_minimize_privileged_containers** · HIGH — Pod does not contain a privileged container
  - _What:_ **Kubernetes Pods** are evaluated for containers configured with `securityContext.privileged: true`, indicating execution in **privileged mode**.
  - _Fix:_ Block `privileged: true` using **Pod Security Admission** at `restricted`. Apply **least privilege**: - Run unprivileged; set `allowPrivilegeEscalation: false` - Drop capabilities; avoid host access - Restrict who can deploy privileged pods with **RBAC** - Use short-lived, audited exceptions only …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_privileged_containers/core_minimize_privileged_containers.metadata.json)
- `trivy` **KSV-0017** · HIGH — Privileged
  - _What:_ Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.
  - _Fix:_ Change 'containers[].securityContext.privileged' to 'false'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/privileged.rego)
- `trivy` **KSV-0118** · HIGH — Default security context configured
  - _What:_ Security context controls the allocation of security parameters for the pod/container/volume, ensuring the appropriate level of protection. Relying on default security context may expose vulnerabilities to potential attacks that rely on privileged access.
  - _Fix:_ To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/default_security_context.rego)
- `kyverno` **disallow-privileged-containers** · MEDIUM — Disallow Privileged Containers
  - _What:_ Privileged mode disables most security mechanisms and must not be allowed. This policy ensures Pods do not call for privileged mode.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-privileged-containers/disallow-privileged-containers.yaml)
- `polaris` **hostProcess** · MEDIUM — Privileged access to the host is disallowed
  - _What:_ Pass: Privileged access to the host check is valid | Fail: Privileged access to the host is disallowed
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostProcess.yaml)
- `trivy` **KSV-0103** · MEDIUM — Access to host process
  - _What:_ Windows pods offer the ability to run HostProcess containers which enable privileged access to the Windows node.
  - _Fix:_ Do not enable 'hostProcess' on any securityContext
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/windows_host_process.rego)
- `checkov` **CKV_K8S_16** · CIS cis-1.3:1.7.1; cis-1.5:5.2.1 — Container should not be privileged
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/PrivilegedContainers.py)
- `checkov` **CKV_K8S_2** · CIS cis-1.3:1.7.1; cis-1.5:5.2.1 — Do not admit privileged containers
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/PrivilegedContainersPSP.py)
- `gatekeeper` **k8spspprivilegedcontainer** — Privileged Container
  - _What:_ Controls the ability of any container to enable privileged mode. Corresponds to the `privileged` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/privileged-containers/template.yaml)
- `kube-bench` **5.2.2** · manual · CIS cis-1.11:5.2.2 — Minimize the admission of privileged containers
  - _What:_ [Pod Security Standards] Minimize the admission of privileged containers
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of privileged containers. Audit: the audit list all pods' containers to retrieve their .securityContext.privileged value. Condition: is_compliant is false if container's `.securityContext.privileged` …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **privileged-container** — Privileged container
  - _What:_ Indicates when deployments have containers running in privileged mode.
  - _Fix:_ Do not run your container as privileged unless it is required.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/privileged.yaml)
- `kube-linter` **privileged-ports** — Privileged ports
  - _What:_ Alert on deployments with privileged ports mapped in containers
  - _Fix:_ Ensure privileged ports [0, 1024] are not mapped within containers.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/privilegedports.yaml)
- `kube-linter` **scc-deny-privileged-container** — Scc deny privileged container
  - _What:_ Indicates when allowPrivilegedContainer SecurityContextConstraints set to true
  - _Fix:_ SecurityContextConstraints has AllowPrivilegedContainer set to "true". Using this option is dangerous, please consider using allowedCapabilities instead. Refer to …
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/scc-deny-privileged-container.yaml)

### Read-only root filesystem  
_5 rules · tools: checkov, gatekeeper, kube-linter, polaris, prowler_

- `polaris` **notReadOnlyRootFilesystem** · MEDIUM — Filesystem should be read only
  - _What:_ Pass: Filesystem is read only | Fail: Filesystem should be read only
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/notReadOnlyRootFilesystem.yaml)
- `prowler` **core_readonly_root_filesystem_enabled** · MEDIUM — Containers should run with a read-only root filesystem
  - _What:_ **Kubernetes Pods** are evaluated to ensure every container sets `readOnlyRootFilesystem: true` in its `securityContext`. A writable root filesystem lets an attacker who gains code execution modify binaries, drop tools, or persist malicious files inside the container.
  - _Fix:_ Set `readOnlyRootFilesystem: true` for every regular, init, and ephemeral container that is part of a Pod spec. Mount writable `emptyDir` volumes only at the specific paths that genuinely need write access (e.g., `/tmp`, `/var/cache`). Enforce this at admission time with custom admission policies …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_readonly_root_filesystem_enabled/core_readonly_root_filesystem_enabled.metadata.json)
- `checkov` **CKV_K8S_22** — Use read-only filesystem for containers where possible
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ReadOnlyFilesystem.py)
- `gatekeeper` **k8spspreadonlyrootfilesystem** — Read Only Root Filesystem
  - _What:_ Requires the use of a read-only root file system by pod containers. Corresponds to the `readOnlyRootFilesystem` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/read-only-root-filesystem/template.yaml)
- `kube-linter` **no-read-only-root-fs** — No read only root fs
  - _What:_ Indicates when containers are running without a read-only root filesystem.
  - _Fix:_ Set readOnlyRootFilesystem to true in the container securityContext.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/read-only-root-fs.yaml)

### Root group / fsGroup  
_3 rules · tools: gatekeeper, kyverno, trivy_

- `kyverno` **validate-userid-groupid-fsgroup** · MEDIUM — Validate User ID, Group ID, and FS Group
  - _What:_ All processes inside a Pod can be made to run with specific user and groupID by setting `runAsUser` and `runAsGroup` respectively. `fsGroup` can be specified to make sure any file created in the volume will have the specified groupID. This policy validates that these fields are set to the defined values.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/restrict-usergroup-fsgroup-id/restrict-usergroup-fsgroup-id.yaml)
- `trivy` **KSV-0116** · LOW — Runs with a root primary or supplementary GID
  - _What:_ According to pod security standard 'Non-root groups', containers should be forbidden from running with a root primary or supplementary GID.
  - _Fix:_ Set 'containers[].securityContext.runAsGroup' to a non-zero integer or leave undefined.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runs_with_a_root_primary_or_supplementary_GID.rego)
- `gatekeeper` **k8spspfsgroup** — FS Group
  - _What:_ Controls allocating an FSGroup that owns the Pod's volumes. Corresponds to the `fsGroup` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/fsgroup/template.yaml)

### Run as non-root user  
_11 rules · tools: checkov, gatekeeper, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `polaris` **runAsRootAllowed** · HIGH — Should not be allowed to run as root
  - _What:_ Pass: Is not allowed to run as root | Fail: Should not be allowed to run as root
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/runAsRootAllowed.yaml)
- `prowler` **core_minimize_root_containers_admission** · HIGH — Pod does not run any container as the root user
  - _What:_ **Kubernetes Pods** are assessed for containers configured to run as the **root user**. The evaluation identifies containers whose security context sets `runAsUser: 0`.
  - _Fix:_ Require non-root execution and enforce **least privilege**: - Set `runAsNonRoot: true` and a non-zero `runAsUser` - Use images with a defined non-root UID - Apply **Pod Security Standards - restricted** or policies to block UID `0` - Use `allowPrivilegeEscalation: false` and drop unnecessary …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_root_containers_admission/core_minimize_root_containers_admission.metadata.json)
- `kubescape` **C-0198** · MEDIUM · CIS cis-v1.10.0:5.2.7; cis-v1.12.0:5.2.7 — Minimize the admission of root containers
  - _What:_ Do not generally permit containers to be run as the root user.
  - _Fix:_ Create a policy for each namespace in the cluster, ensuring that either `MustRunAsNonRoot` or `MustRunAs` with the range of UIDs not including 0, is set.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0198-minimizetheadmissionofrootcontainers.json)
- `kubescape` **C-0218** · MEDIUM · CIS cis-aks-t1.2.0:4.2.6; cis-aks-t1.8.0:4.2.6 — Minimize the admission of root containers
  - _What:_ Do not generally permit containers to be run as the root user.
  - _Fix:_ Create a PSP as described in the Kubernetes documentation, ensuring that the `.spec.runAsUser.rule` is set to either `MustRunAsNonRoot` or `MustRunAs` with the range of UIDs not including 0.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0218-minimizetheadmissionofrootcontainers.json)
- `kyverno` **require-run-as-non-root-user** · MEDIUM — Require Run As Non-Root User
  - _What:_ Containers must be required to run as non-root users. This policy ensures `runAsUser` is either unset or set to a number greater than zero.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/require-run-as-non-root-user/require-run-as-non-root-user.yaml)
- `kyverno` **require-run-as-nonroot** · MEDIUM — Require runAsNonRoot
  - _What:_ Containers must be required to run as non-root. This policy ensures `runAsNonRoot` is set to true.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/require-run-as-nonroot/require-run-as-nonroot.yaml)
- `trivy` **KSV-0001** · MEDIUM — Can elevate its own privileges
  - _What:_ A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.
  - _Fix:_ Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/can_elevate_its_own_privileges.rego)
- `trivy` **KSV-0105** · LOW — Containers must not set runAsUser to 0
  - _What:_ Containers should be forbidden from running with a root UID.
  - _Fix:_ Set 'securityContext.runAsUser' to a non-zero integer or leave undefined.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runs_with_a_root_uid.rego)
- `checkov` **CKV_K8S_40** — Containers should run as a high UID to avoid host conflict
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RootContainersHighUID.py)
- `gatekeeper` **k8spspallowedusers** — Allowed Users
  - _What:_ Controls the user and group IDs of the container and some volumes. Corresponds to the `runAsUser`, `runAsGroup`, `supplementalGroups`, and `fsGroup` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/users/template.yaml)
- `kube-linter` **run-as-non-root** — Run as non root
  - _What:_ Indicates when containers are not set to runAsNonRoot or explicitly use the root group.
  - _Fix:_ Set runAsUser and runAsGroup to non-zero numbers and runAsNonRoot to true in your pod or container securityContext. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ for details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/run-as-non-root.yaml)

### SELinux  
_2 rules · tools: gatekeeper, trivy_

- `trivy` **KSV-0025** · MEDIUM — SELinux custom options set
  - _What:_ According to pod security standard 'SElinux', setting custom SELinux options should be disallowed.
  - _Fix:_ Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/selinux_custom_options_set.rego)
- `gatekeeper` **k8spspselinuxv2** — SELinux V2
  - _What:_ Defines an allow-list of seLinuxOptions configurations for pod containers. Corresponds to a PodSecurityPolicy requiring SELinux configs. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#selinux
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/selinux/template.yaml)

### Seccomp  
_12 rules · tools: checkov, gatekeeper, kube-bench, kubescape, kyverno, prowler, trivy_

- `prowler` **core_seccomp_profile_docker_default** · HIGH — Pod has the docker/default (RuntimeDefault) seccomp profile at pod level or for all containers
  - _What:_ **Kubernetes Pods** and their containers specify the runtime default seccomp profile using `seccompProfile.type: RuntimeDefault` in the security context. The evaluation looks for this setting at the Pod level or per container.
  - _Fix:_ Enforce **least privilege** for syscalls: - Set `seccompProfile.type: RuntimeDefault` on Pods/containers - Use tailored profiles for sensitive workloads - Avoid privileged or unconfined containers; drop unused capabilities - Combine with AppArmor/SELinux and policy guardrails to enforce and audit …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_seccomp_profile_docker_default/core_seccomp_profile_docker_default.metadata.json)
- `kubescape` **C-0210** · MEDIUM · CIS cis-gke-v1.9.0:4.6.2; cis-v1.10.0:5.7.2; cis-v1.12.0:5.6.2 — Ensure that the seccomp profile is set to docker/default in your pod definitions
  - _What:_ Enable `docker/default` seccomp profile in your pod definitions.
  - _Fix:_ Use security context to enable the `docker/default` seccomp profile in your pod definitions. An example is as below: ``` securityContext: seccompProfile: type: RuntimeDefault ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0210-ensurethattheseccompprofileissettodockerdefaultinyourpoddefinitions.json)
- `kyverno` **restrict-seccomp** · MEDIUM — Restrict Seccomp
  - _What:_ The seccomp profile must not be explicitly set to Unconfined. This policy, requiring Kubernetes v1.30 or later, ensures that seccomp is unset or set to `RuntimeDefault` or `Localhost`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/restrict-seccomp/restrict-seccomp.yaml)
- `kyverno` **restrict-seccomp-strict** · MEDIUM — Restrict Seccomp (Strict)
  - _What:_ The seccomp profile in the Restricted group must not be explicitly set to Unconfined but additionally must also not allow an unset value. This policy, requiring Kubernetes v1.30 or later, ensures that seccomp is set to `RuntimeDefault` or `Localhost`. A known issue prevents a policy such as this using `anyPattern` from being persisted properly in Kubernetes 1.23.0-1.23.2.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/restrict-seccomp-strict/restrict-seccomp-strict.yaml)
- `trivy` **KSV-0104** · MEDIUM — Seccomp policies disabled
  - _What:_ A program inside the container can bypass Seccomp protection policies.
  - _Fix:_ Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/seccomp_profile_unconfined.rego)
- `kubescape` **C-0318** · LOW · CIS cis-v1.12.0:4.2.14 — Ensure that the --seccomp-default parameter is set to true
  - _What:_ Enable the RuntimeDefault seccomp profile for all workloads that do not specify one.
  - _Fix:_ Set the parameter, either via the `--seccomp-default` command line argument or the `seccompDefault` setting in the kubelet config file. Setting it to `true` enables the RuntimeDefault profile for workloads that do not declare one. Based on your system, restart the `kubelet` service. For example: …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0318-ensurethattheseccompdefaultparameterissettotrue.json)
- `trivy` **KSV-0030** · LOW — Runtime/Default Seccomp profile not set
  - _What:_ According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.
  - _Fix:_ Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/runtime_default_seccomp_profile_not_set.rego)
- `checkov` **CKV_K8S_31** · CIS cis-1.5:5.7.2 — Ensure that the seccomp profile is set to docker/default or runtime/default
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/Seccomp.py)
- `checkov` **CKV_K8S_32** · CIS cis-1.5:5.7.2 — Ensure default seccomp profile set to docker/default or runtime/default
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/SeccompPSP.py)
- `gatekeeper` **k8spspseccomp** — Seccomp
  - _What:_ Controls the seccomp profile used by containers. Corresponds to the `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccomp
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/seccomp/template.yaml)
- `gatekeeper` **k8spspseccompv2** — Seccomp V2
  - _What:_ Controls the seccomp profile used by containers. Corresponds to the `securityContext.seccompProfile` field. Security contexts from the annotation is not considered as Kubernetes no longer reads security contexts from the annotation.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/seccompv2/template.yaml)
- `kube-bench` **5.6.2** · manual · CIS cis-1.11:5.6.2 — Ensure that the seccomp profile is set to docker/default in your Pod definitions
  - _What:_ [General Policies] Ensure that the seccomp profile is set to docker/default in your Pod definitions
  - _Fix:_ Use `securityContext` to enable the docker/default seccomp profile in your pod definitions. An example is as below: securityContext: seccompProfile: type: RuntimeDefault
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### Sysctls  
_4 rules · tools: gatekeeper, kube-linter, kyverno, trivy_

- `kyverno` **restrict-sysctls** · MEDIUM — Restrict sysctls
  - _What:_ Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed "safe" subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node. This policy ensures that only those "safe" subsets can be specified in a Pod.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/restrict-sysctls/restrict-sysctls.yaml)
- `trivy` **KSV-0026** · MEDIUM — Unsafe sysctl options set
  - _What:_ Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node.
  - _Fix:_ Do not set 'spec.securityContext.sysctls' or set to values in an allowed subset
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/unsafe_sysctl_options_set.rego)
- `gatekeeper` **k8spspforbiddensysctls** — Forbidden Sysctls
  - _What:_ Controls the `sysctl` profile used by containers. Corresponds to the `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy. When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden. The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter. For more information, see …
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/forbidden-sysctls/template.yaml)
- `kube-linter` **unsafe-sysctls** — Unsafe sysctls
  - _What:_ Alert on deployments specifying unsafe sysctls that may lead to severe problems like wrong behavior of containers
  - _Fix:_ Ensure container does not allow unsafe allocation of system resources by removing unsafe sysctls configurations. For more details see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/ …
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/sysctls.yaml)

### TLS / certificates / ciphers  
_1 rules · tools: kubescape_

- `kubescape` **C-0280** · MEDIUM · CIS cis-aks-t1.8.0:4.1.10; cis-v1.10.0:5.1.11; cis-v1.12.0:5.1.11 — Minimize access to the approval sub-resource of certificatesigningrequests objects
  - _What:_ Users with access to the update the `approval` sub-resource of `certificatesigningrequests` objects can approve new client certificates for the Kubernetes API effectively allowing them to create new high-privileged user accounts. This can allow for privilege escalation to full cluster administrator, depending on users configured in the cluster
  - _Fix:_ Where possible, remove access to the `approval` sub-resource of `certificatesigningrequests` objects.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0280-minimizeaccesstocertsigningreq.json)

### Windows HostProcess  
_5 rules · tools: gatekeeper, kube-bench, kubescape, kyverno, prowler_

- `kubescape` **C-0202** · HIGH · CIS cis-v1.10.0:5.2.11; cis-v1.12.0:5.2.10 — Minimize the admission of Windows HostProcess Containers
  - _What:_ Do not generally permit Windows containers to be run with the `hostProcess` flag set to true.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of `hostProcess` containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0202-minimizetheadmissionofwindowshostprocesscontainers.json)
- `prowler` **core_minimize_admission_windows_hostprocess_containers** · HIGH — Pod does not allow Windows HostProcess containers
  - _What:_ **Kubernetes Pods** are evaluated for Windows settings where `securityContext.windowsOptions.hostProcess` is set to `true`, indicating they can run **Windows HostProcess containers**.
  - _Fix:_ Disallow `hostProcess:true` by default using policy-based admission aligned with **Pod Security Standards**. Permit only in tightly controlled contexts; apply **least privilege**, dedicated namespaces, and restricted service accounts; enforce **separation of duties** and monitor usage. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_admission_windows_hostprocess_containers/core_minimize_admission_windows_hostprocess_containers.metadata.json)
- `kyverno` **disallow-host-process** · MEDIUM — Disallow hostProcess
  - _What:_ Windows pods offer the ability to run HostProcess containers which enables privileged access to the Windows node. Privileged access to the host is disallowed in the baseline policy. HostProcess pods are an alpha feature as of Kubernetes v1.22. This policy ensures the `hostProcess` field, if present, is set to `false`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/baseline/disallow-host-process/disallow-host-process.yaml)
- `gatekeeper` **k8spsphostprocess** — Host Process
  - _What:_ Disallows HostProcess containers for Windows pods. HostProcess containers enable privileged access on Windows nodes and must be disallowed in Baseline and Restricted policies. Corresponds to the windowsOptions.hostProcess field in a Pod's securityContext or container securityContext. For more information, see https://kubernetes.io/docs/concepts/security/pod-security-standards/
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/host-process/template.yaml)
- `kube-bench` **5.2.11** · manual · CIS cis-1.11:5.2.11 — Minimize the admission of Windows HostProcess containers
  - _What:_ [Pod Security Standards] Minimize the admission of Windows HostProcess containers
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers that have `.securityContext.windowsOptions.hostProcess` set to `true`.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)

### hostPath volumes  
_12 rules · tools: gatekeeper, kube-bench, kube-linter, kubescape, kyverno, polaris, prowler, trivy_

- `kubescape` **C-0045** · HIGH — Writable hostPath mount
  - _What:_ Mounting host directory to the container can be used by attackers to get access to the underlying host and gain persistence.
  - _Fix:_ Refrain from using the hostPath mount or use the exception mechanism to remove unnecessary notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0045-writablehostpathmount.json)
- `kubescape` **C-0048** · HIGH — HostPath mount
  - _What:_ Mounting host directory to the container can be used by attackers to get access to the underlying host. This control identifies all the pods using hostPath mount.
  - _Fix:_ Remove hostPath mounts unless they are absolutely necessary and use exception mechanism to remove notifications.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0048-hostpathmount.json)
- `prowler` **core_minimize_hostpath_volume_mounts** · HIGH — Pod does not use hostPath volumes
  - _What:_ **Kubernetes Pods** are evaluated for volumes of type `hostPath`, which mount paths from the node filesystem into a pod.
  - _Fix:_ Disallow `hostPath` volumes by default with Pod Security Admission or policy-as-code controls. Permit narrow, read-only exceptions only for trusted system workloads, and prefer Kubernetes-native volume types that do not expose the node filesystem. Steps: 1. Identify the workload that owns the …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/core/core_minimize_hostpath_volume_mounts/core_minimize_hostpath_volume_mounts.metadata.json)
- `trivy` **KSV-0006** · HIGH — hostPath volume mounted with docker.sock
  - _What:_ Mounting docker.sock from the host can give the container full root access to the host.
  - _Fix:_ Do not specify /var/run/docker.socket in 'spec.template.volumes.hostPath.path'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/mounts_docker_socket.rego)
- `trivy` **KSV-0121** · HIGH — Kubernetes resource with disallowed volumes mounted
  - _What:_ HostPath present many security risks and as a security practice it is better to avoid critical host paths mounts.
  - _Fix:_ Do not Set 'spec.volumes[*].hostPath.path' to any of the disallowed volumes.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/Kubernetes_resource_with_disallowed_volumes_mounted.rego)
- `kubescape` **C-0203** · MEDIUM · CIS cis-v1.10.0:5.2.12; cis-v1.12.0:5.2.11 — Minimize the admission of HostPath volumes
  - _What:_ Do not generally admit containers which make use of `hostPath` volumes.
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers which use `hostPath` volumes.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0203-minimizetheadmissionofhostpathvolumes.json)
- `kyverno` **restrict-volume-types** · MEDIUM — Restrict Volume Types
  - _What:_ In addition to restricting HostPath volumes, the restricted pod security profile limits usage of non-core volume types to those defined through PersistentVolumes. This policy blocks any other type of volume other than those in the allow list.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/pod-security-vpol/restricted/restrict-volume-types/restrict-volume-types.yaml)
- `polaris` **hostPathSet** · MEDIUM — HostPath volumes must be forbidden
  - _What:_ Pass: HostPath volumes are not configured | Fail: HostPath volumes must be forbidden
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/hostPathSet.yaml)
- `trivy` **KSV-0023** · MEDIUM — hostPath volumes mounted
  - _What:_ According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden.
  - _Fix:_ Do not set 'spec.volumes[*].hostPath'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/hostpath_volumes_mounted.rego)
- `gatekeeper` **k8spsphostfilesystem** — Host Filesystem
  - _What:_ Controls usage of the host filesystem. Corresponds to the `allowedHostPaths` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/host-filesystem/template.yaml)
- `kube-bench` **5.2.12** · manual · CIS cis-1.11:5.2.12 — Minimize the admission of HostPath volumes
  - _What:_ [Pod Security Standards] Minimize the admission of HostPath volumes
  - _Fix:_ Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with `hostPath` volumes.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kube-linter` **writable-host-mount** — Writable host mount
  - _What:_ Indicates when containers mount a host path as writable.
  - _Fix:_ Set containers to mount host paths as readOnly, if you need to access files on the host.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/writable-host-mount.yaml)

### procMount  
_4 rules · tools: gatekeeper, kube-linter, polaris, trivy_

- `polaris` **procMount** · MEDIUM — Proc mount must not be changed from the default
  - _What:_ Pass: The default /proc masks are set up to reduce attack surface, and should be required | Fail: Proc mount must not be changed from the default
  - [source](https://github.com/FairwindsOps/polaris/blob/4ced8e86db4d6cfe99ed8705ee687b9b9eeb566a/pkg/config/checks/procMount.yaml)
- `trivy` **KSV-0027** · MEDIUM — Non-default /proc masks set
  - _What:_ According to pod security standard '/proc Mount Type', the default /proc masks are set up to reduce attack surface, and should be required.
  - _Fix:_ Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/non_default_proc_masks_set.rego)
- `gatekeeper` **k8spspprocmount** — Proc Mount
  - _What:_ Controls the allowed `procMount` types for the container. Corresponds to the `allowedProcMountTypes` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#allowedprocmounttypes
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/pod-security-policy/proc-mount/template.yaml)
- `kube-linter` **unsafe-proc-mount** — Unsafe proc mount
  - _What:_ Alert on deployments with unsafe /proc mount (procMount=Unmasked) that will bypass the default masking behavior of the container runtime
  - _Fix:_ Ensure container does not unsafely exposes parts of /proc by setting procMount=Default. Unmasked ProcMount bypasses the default masking behavior of the container runtime. See https://kubernetes.io/docs/concepts/security/pod-security-standards/ for more details.
  - [source](https://github.com/stackrox/kube-linter/blob/a4ca2547fc42016044175588e3a266c2639125fb/pkg/builtinchecks/yamls/unsafe-proc-mount.yaml)

### Other  
_20 rules · tools: checkov, gatekeeper, kube-bench, kubescape, kyverno, trivy_

- `kubescape` **C-0211** · HIGH · CIS cis-aks-t1.2.0:4.7.2; cis-aks-t1.8.0:4.7.2; cis-gke-v1.9.0:4.6.3; cis-v1.10.0:5.7.3; cis-v1.12.0:5.6.3 — Apply Security Context to Your Pods and Containers
  - _Fix:_ Follow the Kubernetes documentation and apply security contexts to your pods. For a suggested list of security contexts, you may refer to the CIS Security Benchmark for Docker Containers.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0211-applysecuritycontexttoyourpodsandcontainers.json)
- `kubescape` **C-0316** · HIGH — Agent Sandbox claim override restrictions
  - _What:_ SandboxTemplate should not let claims replace template environment variables or volume claim templates.
  - _Fix:_ Set envVarsInjectionPolicy and volumeClaimTemplatesPolicy to Disallowed or Allowed, not Overrides.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0316-agent-sandbox-claim-overrides.json)
- `kubescape` **C-0002** · MEDIUM — Prevent containers from allowing command execution
  - _What:_ Attackers with relevant permissions can run malicious commands in the context of legitimate containers in the cluster using “kubectl exec” command. This control determines which subjects have permissions to use this command.
  - _Fix:_ It is recommended to prohibit “kubectl exec” command in production environments. It is also recommended not to use subjects with this permission for daily cluster operations.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0002-execintocontainer.json)
- `kubescape` **C-0055** · MEDIUM — Linux hardening
  - _What:_ Containers may be given more privileges than they actually need. This can increase the potential impact of a container compromise.
  - _Fix:_ You can use AppArmor, Seccomp, SELinux and Linux Capabilities mechanisms to restrict containers abilities to utilize unwanted privileges.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0055-linuxhardening.json)
- `kubescape` **C-0026** · LOW — Kubernetes CronJob
  - _What:_ Attackers may use Kubernetes CronJob for scheduling execution of malicious code that would run as a pod in the cluster. This control lists all the CronJobs that exist in the cluster for the user to approve.
  - _Fix:_ Watch Kubernetes CronJobs and make sure they are legitimate.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0026-kubernetescronjob.json)
- `trivy` **KSV-0007** · LOW — Manages /etc/hosts
  - _What:_ Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started.
  - _Fix:_ Do not set 'spec.template.spec.hostAliases'.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/manages_etc_hosts.rego)
- `checkov` **CKV_K8S_1** · CIS cis-1.3:1.7.2; cis-1.5:5.2.2 — Do not admit containers wishing to share the host process ID namespace
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ShareHostPIDPSP.py)
- `checkov` **CKV_K8S_17** · CIS cis-1.3:1.7.2; cis-1.5:5.2.2 — Containers should not share the host process ID namespace
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ShareHostPID.py)
- `checkov` **CKV_K8S_23** · CIS cis-1.3:1.7.6; cis-1.5:5.2.6 — Minimize the admission of root containers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RootContainers.py)
- `checkov` **CKV_K8S_27** — Do not expose the docker daemon socket to containers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/DockerSocketVolume.py)
- `checkov` **CKV_K8S_29** · CIS cis-1.5:5.7.3 — Apply security context to your pods and containers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/PodSecurityContext.py)
- `checkov` **CKV_K8S_30** · CIS cis-1.5:5.7.3 — Apply security context to your containers
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ContainerSecurityContext.py)
- `checkov` **CKV_K8S_6** · CIS cis-1.3:1.7.6; cis-1.5:5.2.6 — Do not admit root containers
  - ⚠ PodSecurityPolicy was removed in Kubernetes 1.25 — map to Pod Security Admission / policy engine instead.
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/RootContainersPSP.py)
- `gatekeeper` **k8sdisallowinteractivetty** — Disallow Interactive TTY Containers
  - _What:_ Requires that objects have the fields `spec.tty` and `spec.stdin` set to false or unset.
  - [source](https://github.com/open-policy-agent/gatekeeper-library/blob/d2b86f87b0c98922d0765f6829bdabd75b3348e5/library/general/disallowinteractive/template.yaml)
- `kube-bench` **5.6.3** · manual · CIS cis-1.11:5.6.3 — Apply SecurityContext to your Pods and Containers
  - _What:_ [General Policies] Apply SecurityContext to your Pods and Containers
  - _Fix:_ Follow the Kubernetes documentation and apply SecurityContexts to your Pods. For a suggested list of SecurityContexts, you may refer to the CIS Security Benchmark for Docker Containers.
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/policies.yaml)
- `kyverno` **deny-exec-by-namespace-label** — Block Pod Exec by Namespace Label
  - _What:_ The `exec` command may be used to gain shell access, or run other commands, in a Pod's container. While this can be useful for troubleshooting purposes, it could represent an attack vector and is discouraged. This policy blocks Pod exec commands based upon a Namespace label `exec=false`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-pod-exec-by-namespace-label/block-pod-exec-by-namespace-label.yaml)
- `kyverno` **deny-exec-by-namespace-name** — Block Pod Exec by Namespace Name
  - _What:_ The `exec` command may be used to gain shell access, or run other commands, in a Pod's container. While this can be useful for troubleshooting purposes, it could represent an attack vector and is discouraged. This policy blocks Pod exec commands to Pods in a Namespace called `pci`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-pod-exec-by-namespace/block-pod-exec-by-namespace.yaml)
- `kyverno` **deny-exec-by-pod-and-container** — Block Pod Exec by Pod and Container
  - _What:_ The `exec` command may be used to gain shell access, or run other commands, in a Pod's container. While this can be useful for troubleshooting purposes, it could represent an attack vector and is discouraged. This policy blocks Pod exec commands to containers named `nginx` in Pods starting with name `myapp-maintenance`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-pod-exec-by-pod-and-container/block-pod-exec-by-pod-and-container.yaml)
- `kyverno` **deny-exec-by-pod-label** — Block Pod Exec by Pod Label
  - _What:_ The `exec` command may be used to gain shell access, or run other commands, in a Pod's container. While this can be useful for troubleshooting purposes, it could represent an attack vector and is discouraged. This policy blocks Pod exec commands to Pods having the label `exec=false`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-pod-exec-by-pod-label/block-pod-exec-by-pod-label.yaml)
- `kyverno` **deny-exec-by-pod-name** — Block Pod Exec by Pod Name
  - _What:_ The `exec` command may be used to gain shell access, or run other commands, in a Pod's container. While this can be useful for troubleshooting purposes, it could represent an attack vector and is discouraged. This policy blocks Pod exec commands to Pods beginning with the name `myapp-maintenance-`.
  - [source](https://github.com/kyverno/policies/blob/36340047222cf73e8ef2766adeaff46f2aad2362/other-vpol/block-pod-exec-by-pod-name/block-pod-exec-by-pod-name.yaml)


## etcd

### Encryption at rest / KMS  
_5 rules · tools: kubescape, prowler, trivy_

- `kubescape` **C-0141** · HIGH · CIS cis-v1.10.0:1.2.27; cis-v1.12.0:1.2.27 — Ensure that the API Server --encryption-provider-config argument is set as appropriate
  - _What:_ Encrypt etcd key-value store.
  - _Fix:_ Follow the Kubernetes documentation and configure a `EncryptionConfig` file. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the `--encryption-provider-config` parameter to the path of that file: ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0141-ensurethattheapiserverencryptionproviderconfigargumentissetasappropriate.json)
- `kubescape` **C-0142** · HIGH · CIS cis-v1.10.0:1.2.28; cis-v1.12.0:1.2.28 — Ensure that encryption providers are appropriately configured
  - _What:_ Where `etcd` encryption is used, appropriate providers should be configured.
  - _Fix:_ Follow the Kubernetes documentation and configure a `EncryptionConfig` file. In this file, choose `aescbc`, `kms` or `secretbox` as the encryption provider.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0142-ensurethatencryptionprovidersareappropriatelyconfigured.json)
- `prowler` **apiserver_encryption_provider_config_set** · HIGH — API server pod has the --encryption-provider-config argument set
  - _What:_ **Kubernetes API server** pods include `--encryption-provider-config`, supplying an EncryptionConfiguration to apply **encryption at rest** to selected API resources stored in etcd.
  - _Fix:_ Enable **encryption at rest** with an `EncryptionConfiguration` and run with `--encryption-provider-config` using a non-`identity` provider (prefer `kms v2`). Apply **least privilege** to key/KMS access, rotate keys, restrict config file access, keep settings consistent across API servers, and …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_encryption_provider_config_set/apiserver_encryption_provider_config_set.metadata.json)
- `kubescape` **C-0066** · MEDIUM · CIS cis-eks-t1.7.0:5.3.1; cis-eks-t1.8.0:5.3.1; cis-gke-v1.9.0:5.3.1 — Secret/etcd encryption enabled
  - _What:_ All Kubernetes Secrets are stored primarily in etcd therefore it is important to encrypt it.
  - _Fix:_ Turn on the etcd encryption in your cluster, for more see the vendor documentation.
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0066-secretetcdencryptionenabled.json)
- `trivy` **KCV-0030** · LOW — Ensure that the --encryption-provider-config argument is set as appropriate
  - _What:_ [API server] Encrypt etcd key-value store.
  - _Fix:_ Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_encryption_provider_config.rego)

### Image signing & verification  
_1 rules · tools: prowler_

- `prowler` **etcd_no_peer_auto_tls** · HIGH — Etcd pod does not use automatically generated self-signed certificates for peer TLS connections
  - _What:_ **Etcd peer TLS** configuration is evaluated by checking etcd containers for the `--peer-auto-tls` flag. Presence of `--peer-auto-tls` indicates peers use automatically generated self-signed certificates for inter-peer connections.
  - _Fix:_ Disable `--peer-auto-tls` and use **mTLS** with a trusted CA issuing unique per-member peer certificates. Enforce SAN validation and, *where supported*, peer certificate authentication. Apply **least privilege**, separate CAs for peers/clients, rotate keys, and monitor certificate expiry and peer …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_no_peer_auto_tls/etcd_no_peer_auto_tls.metadata.json)

### TLS / certificates / ciphers  
_33 rules · tools: checkov, kube-bench, kubescape, prowler, trivy_

- `prowler` **apiserver_etcd_cafile_set** · CRITICAL — API server pod has the --etcd-cafile argument set
  - _What:_ **Kubernetes API server** uses an **etcd CA file** via `--etcd-cafile` to verify etcd's TLS certificate. This evaluates whether API server containers specify that CA file, anchoring TLS trust for etcd connections.
  - _Fix:_ Anchor etcd connections in **mutual TLS**: provide a trusted CA (`--etcd-cafile`) and unique client credentials, rotate keys, and prefer strong ciphers. Apply **least privilege** and **network segmentation** so only API servers can reach etcd; disable plaintext or unauthenticated access. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_etcd_cafile_set/apiserver_etcd_cafile_set.metadata.json)
- `prowler` **apiserver_etcd_tls_config** · CRITICAL — API server pod has --etcd-certfile and --etcd-keyfile configured for etcd TLS
  - _What:_ **Kubernetes API server** uses **TLS** for its etcd client connection, signaled by `--etcd-certfile` and `--etcd-keyfile` in the API server pod arguments. This evaluates whether client-certificate authentication is configured between the API server and etcd.
  - _Fix:_ Enforce **mutual TLS** between API server and etcd with trusted CAs and unique client certificates. Restrict etcd network access to control-plane nodes, rotate keys, and monitor certificate expiry. Apply **least privilege** and **defense in depth** using private networking and firewall policies. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/apiserver/apiserver_etcd_tls_config/apiserver_etcd_tls_config.metadata.json)
- `kubescape` **C-0140** · HIGH · CIS cis-v1.10.0:1.2.26; cis-v1.12.0:1.2.26 — Ensure that the API Server --etcd-cafile argument is set as appropriate
  - _What:_ etcd should be configured to make use of TLS encryption for client connections.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the etcd certificate authority file parameter. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0140-ensurethattheapiserveretcdcafileargumentissetasappropriate.json)
- `kubescape` **C-0153** · HIGH · CIS cis-v1.10.0:2.1; cis-v1.12.0:2.1 — Ensure that the --cert-file and --key-file arguments are set as appropriate
  - _What:_ Configure TLS encryption for the etcd service.
  - _Fix:_ Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and set the below parameters. ``` --cert-file=</path/to/ca-file> --key-file=</path/to/key-file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0153-ensurethatthecertfileandkeyfileargumentsaresetasappropriate.json)
- `kubescape` **C-0154** · HIGH · CIS cis-v1.10.0:2.2; cis-v1.12.0:2.2 — Ensure that the --client-cert-auth argument is set to true
  - _What:_ Enable client authentication on etcd service.
  - _Fix:_ Edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and set the below parameter. ``` --client-cert-auth="true" ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0154-ensurethattheclientcertauthargumentissettotrue.json)
- `kubescape` **C-0156** · HIGH · CIS cis-v1.10.0:2.4; cis-v1.12.0:2.4 — Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - _What:_ etcd should be configured to make use of TLS encryption for peer connections.
  - _Fix:_ Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and set the below parameters. ``` --peer-client-file=</path/to/peer-cert-file> …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0156-ensurethatthepeercertfileandpeerkeyfileargumentsaresetasappropriate.json)
- `kubescape` **C-0157** · HIGH · CIS cis-v1.10.0:2.5; cis-v1.12.0:2.5 — Ensure that the --peer-client-cert-auth argument is set to true
  - _What:_ etcd should be configured for peer authentication.
  - _Fix:_ Edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and set the below parameter. ```--peer-client-cert-auth=true```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0157-ensurethatthepeerclientcertauthargumentissettotrue.json)
- `kubescape` **C-0159** · HIGH · CIS cis-v1.10.0:2.7; cis-v1.12.0:2.7 — Ensure that a unique Certificate Authority is used for etcd
  - _What:_ Use a different certificate authority for etcd from the one used for Kubernetes.
  - _Fix:_ Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service. Then, edit the etcd pod specification file `/etc/kubernetes/manifests/etcd.yaml` on the master node and set the below parameter. ``` --trusted-ca-file=</path/to/ca-file> ```
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0159-ensurethatauniquecertificateauthorityisusedforetcd.json)
- `prowler` **etcd_client_cert_auth** · HIGH — Etcd pod has client certificate authentication enabled (--client-cert-auth=true)
  - _What:_ **Etcd** is configured to require **TLS client certificate authentication** when the etcd container includes `--client-cert-auth`, so client access is validated with trusted certificates.
  - _Fix:_ Enforce **mutual TLS** for etcd clients by requiring validated certificates (`--client-cert-auth=true`) issued by a trusted CA. Restrict network access to etcd to API servers, rotate keys regularly, and apply **least privilege** and **separation of duties** for certificate management. Steps: 1. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_client_cert_auth/etcd_client_cert_auth.metadata.json)
- `prowler` **etcd_no_auto_tls** · HIGH — Etcd pod has --auto-tls disabled
  - _What:_ **Etcd** configuration is reviewed for the `--auto-tls` option, which enables automatically generated self-signed certificates for client TLS. Presence of this flag indicates self-signed TLS is used; absence indicates client TLS relies on externally managed certificates.
  - _Fix:_ Disable `--auto-tls` and use **CA-signed certificates** with **mutual TLS** for etcd clients. Apply managed PKI to enforce trusted CAs, rotate and revoke keys, and prefer modern TLS versions and strong cipher suites. Monitor certificate expiry and limit access per **least privilege** for **defense …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_no_auto_tls/etcd_no_auto_tls.metadata.json)
- `prowler` **etcd_peer_client_cert_auth** · HIGH — Etcd pod has peer client certificate authentication enabled
  - _What:_ **Etcd** requires **peer client certificate authentication** for inter-member traffic via `--peer-client-cert-auth=true` set in the etcd container command
  - _Fix:_ Enforce **mTLS** for etcd peers with client certificate auth. Use a dedicated CA, validate SANs, and apply **least privilege** to issued certs. Rotate and revoke certificates regularly, restrict network access to peer ports, and avoid auto-generated self-signed peer TLS to maintain strong identity …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_peer_client_cert_auth/etcd_peer_client_cert_auth.metadata.json)
- `prowler` **etcd_peer_tls_config** · HIGH — Etcd pod uses TLS for peer connections
  - _What:_ **Etcd peer communication** is treated as secure when **TLS** is configured with a peer certificate and key (e.g., `--peer-cert-file` and `--peer-key-file`). The assessment inspects etcd containers for these options to determine whether server-to-server traffic is encrypted and authenticated.
  - _Fix:_ Enforce **TLS** for etcd peer communication with unique certificates per member and mutual authentication. Apply strong cipher suites and modern protocol versions, rotate keys, and separate CAs for peers and clients. Limit network access to peer ports to trusted nodes, following **least …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_peer_tls_config/etcd_peer_tls_config.metadata.json)
- `prowler` **etcd_tls_encryption** · HIGH — Etcd pod has TLS encryption configured
  - _What:_ **Etcd pods** are assessed for **TLS-enabled client communication**, indicated by `--cert-file` and `--key-file` in container arguments, showing that Kubernetes API state traffic is encrypted in transit.
  - _Fix:_ Enforce **mTLS** for etcd client and peer traffic and disable plaintext listeners. Restrict access to etcd to control-plane components via tight network policies and firewalls. Use strong TLS versions/ciphers, rotate certificates, and safeguard keys, applying **least privilege** and **defense in …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_tls_encryption/etcd_tls_encryption.metadata.json)
- `prowler` **etcd_unique_ca** · HIGH — Etcd pod uses a unique Certificate Authority distinct from the Kubernetes API server CA
  - _What:_ **Etcd** configuration is assessed to ensure it trusts a **unique Certificate Authority** via `--trusted-ca-file`, distinct from the API server's `--client-ca-file`. If the same CA file is used, etcd shares the cluster CA; differing files imply separation, though CA content should still be verified.
  - _Fix:_ Adopt a **separate PKI** for etcd: issue client and peer certs from an etcd-only CA and trust only that CA. Enforce mTLS (`--client-cert-auth`, `--peer-client-cert-auth`), avoid `--auto-tls`, rotate keys independently, and apply **least privilege** to CA issuance with regular certificate audits. …
  - [source](https://github.com/prowler-cloud/prowler/blob/04511f339e2cc13857f8d876d689857429f65edf/prowler/providers/kubernetes/services/etcd/etcd_unique_ca/etcd_unique_ca.metadata.json)
- `trivy` **KCV-0029** · LOW — Ensure that the --etcd-cafile argument is set as appropriate
  - _What:_ [API server] etcd should be configured to make use of TLS encryption for client connections.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate authority file parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_etcd_cafile.rego)
- `trivy` **KCV-0042** · LOW — Ensure that the --cert-file and --key-file arguments are set as appropriate
  - _What:_ [etcd] Configure TLS encryption for the etcd service.
  - _Fix:_ Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_cert_file_and_key_file.rego)
- `trivy` **KCV-0043** · LOW — Ensure that the --client-cert-auth argument is set to true
  - _What:_ [etcd] Enable client authentication on etcd service.
  - _Fix:_ Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_client_cert_auth.rego)
- `trivy` **KCV-0044** · LOW — Ensure that the --auto-tls argument is not set to true
  - _What:_ [etcd] Do not use self-signed certificates for TLS.
  - _Fix:_ Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter or set it to false.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_auto_tls.rego)
- `trivy` **KCV-0045** · LOW — Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - _What:_ [etcd] etcd should be configured to make use of TLS encryption for peer connections.
  - _Fix:_ Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_peer_cert_file_and_key_file.rego)
- `trivy` **KCV-0046** · LOW — Ensure that the --peer-client-cert-auth argument is set to true
  - _What:_ [etcd] etcd should be configured for peer authentication.
  - _Fix:_ Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_peer_client_cert_auth.rego)
- `trivy` **KCV-0047** · LOW — Ensure that the --peer-auto-tls argument is not set to true
  - _What:_ [etcd] Do not use self-signed certificates for TLS.
  - _Fix:_ Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --peer-auto-tls parameter or set it to false.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/etcd_peer_auto_tls.rego)
- `checkov` **CKV_K8S_116** · CIS cis-1.6:2.1 — Ensure that the --cert-file and --key-file arguments are set as appropriate
  - _What:_ [etcd] Ensure that the --cert-file and --key-file arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/EtcdCertAndKey.py)
- `checkov` **CKV_K8S_117** · CIS cis-1.6:2.2 — Ensure that the --client-cert-auth argument is set to true
  - _What:_ [etcd] Ensure that the --client-cert-auth argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/EtcdClientCertAuth.py)
- `checkov` **CKV_K8S_118** · CIS cis-1.6:2.3 — Ensure that the --auto-tls argument is not set to true
  - _What:_ [etcd] Ensure that the --auto-tls argument is not set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/EtcdAutoTls.py)
- `checkov` **CKV_K8S_119** — Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - _What:_ [etcd] Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/EtcdPeerFiles.py)
- `checkov` **CKV_K8S_121** — Ensure that the --peer-client-cert-auth argument is set to true
  - _What:_ [etcd] Ensure that the --peer-client-cert-auth argument is set to true
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/PeerClientCertAuthTrue.py)
- `kube-bench` **2.1** · CIS cis-1.11:2.1 — Ensure that the --cert-file and --key-file arguments are set as appropriate
  - _What:_ [Etcd Node Configuration] Ensure that the --cert-file and --key-file arguments are set as appropriate
  - _Fix:_ Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters. --cert-file=</path/to/ca-file> --key-file=</path/to/key-file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.2** · CIS cis-1.11:2.2 — Ensure that the --client-cert-auth argument is set to true
  - _What:_ [Etcd Node Configuration] Ensure that the --client-cert-auth argument is set to true
  - _Fix:_ Edit the etcd pod specification file $etcdconf on the master node and set the below parameter. --client-cert-auth="true"
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.3** · CIS cis-1.11:2.3 — Ensure that the --auto-tls argument is not set to true
  - _What:_ [Etcd Node Configuration] Ensure that the --auto-tls argument is not set to true
  - _Fix:_ Edit the etcd pod specification file $etcdconf on the master node and either remove the --auto-tls parameter or set it to false. --auto-tls=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.4** · CIS cis-1.11:2.4 — Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - _What:_ [Etcd Node Configuration] Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
  - _Fix:_ Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file $etcdconf on the master node and set the below parameters. --peer-client-file=</path/to/peer-cert-file> --peer-key-file=</path/to/peer-key-file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.5** · CIS cis-1.11:2.5 — Ensure that the --peer-client-cert-auth argument is set to true
  - _What:_ [Etcd Node Configuration] Ensure that the --peer-client-cert-auth argument is set to true
  - _Fix:_ Edit the etcd pod specification file $etcdconf on the master node and set the below parameter. --peer-client-cert-auth=true
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.6** · CIS cis-1.11:2.6 — Ensure that the --peer-auto-tls argument is not set to true
  - _What:_ [Etcd Node Configuration] Ensure that the --peer-auto-tls argument is not set to true
  - _Fix:_ Edit the etcd pod specification file $etcdconf on the master node and either remove the --peer-auto-tls parameter or set it to false. --peer-auto-tls=false
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)
- `kube-bench` **2.7** · manual · CIS cis-1.11:2.7 — Ensure that a unique Certificate Authority is used for etcd
  - _What:_ [Etcd Node Configuration] Ensure that a unique Certificate Authority is used for etcd
  - _Fix:_ [Manual test] Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service. Then, edit the etcd pod specification file $etcdconf on the master node and set the below parameter. --trusted-ca-file=</path/to/ca-file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/etcd.yaml)

### etcd TLS / client auth  
_4 rules · tools: checkov, kube-bench, kubescape, trivy_

- `kubescape` **C-0137** · HIGH · CIS cis-v1.10.0:1.2.23; cis-v1.12.0:1.2.23 — Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - _What:_ etcd should be configured to make use of TLS encryption for client connections.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the master node and set the etcd certificate and key file parameters. ``` …
  - [source](https://github.com/kubescape/regolibrary/blob/e67b7d42a0d9c855b6617a53a56cd1f3f434e63e/controls/C-0137-ensurethattheapiserveretcdcertfileandetcdkeyfileargumentsaresetasappropriate.json)
- `trivy` **KCV-0026** · LOW — Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - _What:_ [API server] etcd should be configured to make use of TLS encryption for client connections.
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters.
  - [source](https://github.com/aquasecurity/trivy-checks/blob/3ae9f4cc196767047a2a1fdae2d24a82944dfd6b/checks/kubernetes/apiserver_etcd_certfile_and_keyfile.rego)
- `checkov` **CKV_K8S_99** — Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - _What:_ [API server] Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerEtcdCertAndKey.py)
- `kube-bench` **1.2.23** · CIS cis-1.11:1.2.23 — Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - _What:_ [API Server] Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the etcd certificate and key file parameters. --etcd-certfile=<path/to/client-certificate-file> …
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

### Other  
_2 rules · tools: checkov, kube-bench_

- `checkov` **CKV_K8S_102** — Ensure that the --etcd-cafile argument is set as appropriate
  - _What:_ [API server] Ensure that the --etcd-cafile argument is set as appropriate
  - [source](https://github.com/bridgecrewio/checkov/blob/29ba1746d0eabf0fbf97c3c53f99cb44e367ba8d/checkov/kubernetes/checks/resource/k8s/ApiServerEtcdCaFile.py)
- `kube-bench` **1.2.26** · CIS cis-1.11:1.2.26 — Ensure that the --etcd-cafile argument is set as appropriate
  - _What:_ [API Server] Ensure that the --etcd-cafile argument is set as appropriate
  - _Fix:_ Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file $apiserverconf on the control plane node and set the etcd certificate authority file parameter. --etcd-cafile=<path/to/ca-file>
  - [source](https://github.com/aquasecurity/kube-bench/blob/e0ffe5da8fe16192074773b7a7b20da825f15827/cfg/cis-1.11/master.yaml)

