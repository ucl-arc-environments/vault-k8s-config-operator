/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultK8sConfigSpec defines the desired state of VaultK8sConfig
type VaultK8sConfigSpec struct {
	// vaultAddress is the URL of the external Vault instance.
	// +kubebuilder:validation:Pattern=`^https?://.+$`
	VaultAddress string `json:"vaultAddress"`

	// vaultNamespace is the Vault Enterprise namespace used for API requests.
	// +optional
	VaultNamespace string `json:"vaultNamespace,omitempty"`

	// auth defines how the operator authenticates to Vault.
	Auth VaultAuthSpec `json:"auth"`

	// engine defines the Kubernetes secret engine mount path and desired config.
	Engine KubernetesSecretEngineSpec `json:"engine"`
}

// VaultAuthSpec defines Vault authentication configuration.
type VaultAuthSpec struct {
	// tokenSecretRef references a Kubernetes Secret key that contains a Vault token.
	TokenSecretRef SecretKeyRef `json:"tokenSecretRef"`
}

// SecretKeyRef points to a key inside a Secret in the same namespace as the CR.
type SecretKeyRef struct {
	// name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// key is the data key in the Secret.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// KubernetesSecretEngineSpec defines desired state for Vault's Kubernetes secret engine config.
type KubernetesSecretEngineSpec struct {
	// mountPath is the path where the Kubernetes secret engine is enabled in Vault.
	// +kubebuilder:validation:MinLength=1
	MountPath string `json:"mountPath"`

	// kubernetesHost is the Kubernetes API server URL used by Vault.
	// +kubebuilder:validation:Pattern=`^https?://.+$`
	KubernetesHost string `json:"kubernetesHost"`

	// clusterCredentialsSecretRef references a Secret that contains JWT and CA cert data.
	// When omitted, the operator provisions a vault-auth ServiceAccount, its long-lived token
	// Secret, a ClusterRole, and a ClusterRoleBinding in the same namespace as the CR and
	// uses that token Secret for JWT and CA cert extraction.
	// +optional
	ClusterCredentialsSecretRef *ClusterCredentialsSecretRef `json:"clusterCredentialsSecretRef,omitempty"`
}

// ClusterCredentialsSecretRef points to a Secret and key names for JWT and CA certificate.
type ClusterCredentialsSecretRef struct {
	// name is the Secret name that stores cluster credentials.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// namespace is the namespace of the Secret. When omitted, defaults to the CR's namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// jwtKey is the key in the Secret data that stores the JWT used by Vault.
	// +kubebuilder:default="token"
	// +optional
	JWTKey string `json:"jwtKey,omitempty"`

	// caCertKey is the key in the Secret data that stores the Kubernetes CA certificate.
	// +kubebuilder:default="ca.crt"
	// +optional
	CACertKey string `json:"caCertKey,omitempty"`
}

// VaultK8sConfigStatus defines the observed state of VaultK8sConfig.
type VaultK8sConfigStatus struct {
	// observedGeneration is the most recent generation reconciled by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the VaultK8sConfig resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VaultK8sConfig is the Schema for the vaultk8sconfigs API
type VaultK8sConfig struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of VaultK8sConfig
	// +required
	Spec VaultK8sConfigSpec `json:"spec"`

	// status defines the observed state of VaultK8sConfig
	// +optional
	Status VaultK8sConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VaultK8sConfigList contains a list of VaultK8sConfig
type VaultK8sConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VaultK8sConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultK8sConfig{}, &VaultK8sConfigList{})
}
