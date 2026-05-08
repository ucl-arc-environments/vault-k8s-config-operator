# vault-k8s-config-operator

This repository builds a [Kubernetes
Operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) which
can be used to configure a pre-existing [Kubernetes Secrets
Engine](https://developer.hashicorp.com/vault/docs/secrets/kubernetes) in
[HashiCorp Vault](https://www.hashicorp.com/en/products/vault) or its open
source equivalent [OpenBao](https://openbao.org/). This is primarily for
stand-alone clusters - i.e. external to the Vault instance. After the
configuration is created, cluster authentication tokens can be issued by Vault
and used in automation to deploy resources to a cluster.

The operator adds a `VaultK8sConfig` Custom Resource Definition to the cluster.
CRs are created as follows:

```yaml
apiVersion: environments.arc.ucl/v1
kind: VaultK8sConfig
metadata:
  name: my-cluster-config
  namespace: vault-k8s-config-operator-system
spec:
  auth:
    tokenSecretRef:
      name: vault-token
      key: token
  engine:
    clusterCredentialsSecretRef:
      name: vault-auth
      namespace: vault-auth
    kubernetesHost: https://10.10.10.10:6443
    mountPath: kubernetes
  vaultAddress: https://your.vault.deployment.url
```

The `auth` spec field references an in-cluster `Secret` holding a token which is
used to authenticate with Vault. This is the only authentication method
supported by this operator.

The `engine.clusterCredentialsSecretRef` spec field is optional and references a
`Secret` of type `kubernetes.io/service-account-token` which can pre-exist in
the cluster to be used by Vault when issuing cluster authentication tokens. If
not present the operator will create and manage this `ServiceAccount` and
associated RBAC resources.
