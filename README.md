# vault-k8s-config-operator

A Kubernetes operator which configures a [Vault Kubernetes Secrets
Engine](https://developer.hashicorp.com/vault/docs/secrets/kubernetes) in an
instance of Vault running externally to the cluster. This will effectively
register the cluster with Vault which can then issue authentication tokens.

## Description

The operator watches for and reconciles `VaultK8sConfig` resources. This CRD
authenticates to Vault using a token in a pre-deployed `Secret` and uses the
Vault API to write a configuration to a Kubernetes Secrets Engine mount. The
path to the mount is provided by the user as part of the `VaultK8sConfig` spec
and must exist in Vault prior to attempting to configure it with this operator -
this operator will not create the mount path if it does not exist.

A `ServiceAccount` must exist within the cluster which Vault can subsequently
use to issue authentication tokens for the cluster. This can be created upfront
by the user or the operator can optionally generate the `ServiceAccount` and
accompanying RBAC machinary.

If using the operator to generate the `ServiceAccount` and associated `Secret`,
a `VautK8sConfig` can be defined as follows:

```yaml
apiVersion: environments.arc.ucl/v1
kind: VaultK8sConfig
metadata:
  name: example-vault-kubernetes-config
  namespace: vault-k8s-config-operator-system
spec:
  auth:
    tokenSecretRef:
      name: vault-token
      key: token
  engine:
    kubernetesHost: https://kubernetes.default.svc
    mountPath: kubernetes
  vaultAddress: http://host.docker.internal:8200
```

Otherwise use the `ClusterCredentialsSecretRef` spec field to refer to the
existing secret:

```yaml
apiVersion: environments.arc.ucl/v1
kind: VaultK8sConfig
metadata:
  name: example-vault-kubernetes-config
  namespace: vault-k8s-config-operator-system
spec:
  auth:
    tokenSecretRef:
      name: vault-token
      key: token
  ClusterCredentialsSecretRef:
    name: vault-auth
    namespace: vault-auth
    JWTKey: token
    CACertKey: ca.crt
  engine:
    kubernetesHost: https://kubernetes.default.svc
    mountPath: kubernetes
  vaultAddress: http://host.docker.internal:8200
```

## API Version
The current custom resource API version is `environments.arc.ucl/v1`.

Use the sample in `config/samples/environments.arc.ucl_v1_vaultk8sconfig.yaml`
as a starting point.

## Getting Started

### Prerequisites
- go version v1.24.6+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
