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

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "vault-k8s-config-operator/api/v1"
)

var _ = Describe("VaultK8sConfig Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()
		const tokenSecretName = "vault-token"
		const clusterCredentialsSecretName = "cluster-credentials"
		const clusterCredentialsNamespace = "user-cluster-credentials"

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		vaultk8sconfig := &v1.VaultK8sConfig{}

		BeforeEach(func() {
			By("creating required secret references")
			clusterCredentialsNamespaceResource := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: clusterCredentialsNamespace},
			}
			if err := k8sClient.Create(ctx, clusterCredentialsNamespaceResource); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			tokenSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tokenSecretName,
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("vault-token-value"),
				},
			}
			if err := k8sClient.Create(ctx, tokenSecret); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			clusterCredentialsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterCredentialsSecretName,
					Namespace: clusterCredentialsNamespace,
				},
				Data: map[string][]byte{
					"token":  []byte("jwt-value"),
					"ca.crt": []byte("ca-cert-value"),
				},
			}
			if err := k8sClient.Create(ctx, clusterCredentialsSecret); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			By("creating the custom resource for the Kind VaultK8sConfig")
			err := k8sClient.Get(ctx, typeNamespacedName, vaultk8sconfig)
			if err != nil && errors.IsNotFound(err) {
				resource := &v1.VaultK8sConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: v1.VaultK8sConfigSpec{
						VaultAddress: "https://vault.example.com",
						Auth: v1.VaultAuthSpec{
							TokenSecretRef: v1.SecretKeyRef{
								Name: tokenSecretName,
								Key:  "token",
							},
						},
						Engine: v1.KubernetesSecretEngineSpec{
							MountPath:      "kubernetes",
							KubernetesHost: "https://kubernetes.default.svc",
							ClusterCredentialsSecretRef: &v1.ClusterCredentialsSecretRef{
								Name:      clusterCredentialsSecretName,
								Namespace: clusterCredentialsNamespace,
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &v1.VaultK8sConfig{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			if containsString(resource.Finalizers, vaultAuthFinalizer) {
				resourceCopy := resource.DeepCopy()
				resourceCopy.Finalizers = removeString(resourceCopy.Finalizers, vaultAuthFinalizer)
				Expect(k8sClient.Update(ctx, resourceCopy)).To(Succeed())
			}

			By("Cleanup the specific resource instance VaultK8sConfig")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			By("Cleanup secret references")
			for secretName, namespace := range map[string]string{tokenSecretName: "default", clusterCredentialsSecretName: clusterCredentialsNamespace} {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
				if err == nil {
					Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
				}
			}
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &VaultK8sConfigReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				ConfigureSecretEngine: func(context.Context, VaultSecretEngineConfig) error {
					return nil
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should mark the resource failed when Vault mount verification fails", func() {
			By("Reconciling the resource with a failing Vault configuration step")
			controllerReconciler := &VaultK8sConfigReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				ConfigureSecretEngine: func(context.Context, VaultSecretEngineConfig) error {
					return fmt.Errorf("Kubernetes secret engine mount %q not found", "kubernetes")
				},
			}

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(defaultRequeueDelay))

			current := &v1.VaultK8sConfig{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, current)).To(Succeed())
			readyCondition := meta.FindStatusCondition(current.Status.Conditions, conditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(conditionReasonFailed))
			Expect(readyCondition.Message).To(ContainSubstring(`mount "kubernetes" not found`))
		})
	})

	Context("When reconciling a resource with default vault-auth provisioning", func() {
		const defaultResourceName = "test-resource-default"
		const defaultTokenSecretName = "vault-token-default"

		ctx := context.Background()

		defaultNamespacedName := types.NamespacedName{
			Name:      defaultResourceName,
			Namespace: "default",
		}

		BeforeEach(func() {
			By("creating the Vault token Secret")
			tokenSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      defaultTokenSecretName,
					Namespace: "default",
				},
				Data: map[string][]byte{"token": []byte("vault-token-value")},
			}
			if err := k8sClient.Create(ctx, tokenSecret); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			By("creating the custom resource without clusterCredentialsSecretRef")
			resource := &v1.VaultK8sConfig{}
			err := k8sClient.Get(ctx, defaultNamespacedName, resource)
			if err != nil && errors.IsNotFound(err) {
				resource = &v1.VaultK8sConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      defaultResourceName,
						Namespace: "default",
					},
					Spec: v1.VaultK8sConfigSpec{
						VaultAddress: "https://vault.example.com",
						Auth: v1.VaultAuthSpec{
							TokenSecretRef: v1.SecretKeyRef{
								Name: defaultTokenSecretName,
								Key:  "token",
							},
						},
						Engine: v1.KubernetesSecretEngineSpec{
							MountPath:      "kubernetes",
							KubernetesHost: "https://kubernetes.default.svc",
							// ClusterCredentialsSecretRef intentionally omitted
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &v1.VaultK8sConfig{}
			err := k8sClient.Get(ctx, defaultNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			if containsString(resource.Finalizers, vaultAuthFinalizer) {
				resourceCopy := resource.DeepCopy()
				resourceCopy.Finalizers = removeString(resourceCopy.Finalizers, vaultAuthFinalizer)
				Expect(k8sClient.Update(ctx, resourceCopy)).To(Succeed())
			}
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			tokenSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: defaultTokenSecretName, Namespace: "default"}, tokenSecret); err == nil {
				Expect(k8sClient.Delete(ctx, tokenSecret)).To(Succeed())
			}

			vaultAuthSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "vault-auth", Namespace: vaultAuthNamespace}, vaultAuthSecret); err == nil {
				Expect(k8sClient.Delete(ctx, vaultAuthSecret)).To(Succeed())
			}

			vaultAuthNamespaceResource := &corev1.Namespace{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: vaultAuthNamespace}, vaultAuthNamespaceResource); err == nil {
				Expect(k8sClient.Delete(ctx, vaultAuthNamespaceResource)).To(Succeed())
			}
		})

		It("should provision vault-auth resources and reconcile successfully", func() {
			By("Reconciling with a stub provisioner that pre-creates vault-auth credentials")
			controllerReconciler := &VaultK8sConfigReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				EnsureVaultAuthResources: func(ctx context.Context) error {
					secret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: vaultAuthNamespace},
						Data: map[string][]byte{
							"token":  []byte("jwt-value"),
							"ca.crt": []byte("ca-cert-value"),
						},
					}
					if err := k8sClient.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
						return err
					}
					return nil
				},
				ConfigureSecretEngine: func(context.Context, VaultSecretEngineConfig) error {
					return nil
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: defaultNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When provisioning default vault-auth RBAC resources", func() {
		ctx := context.Background()
		const namespace = vaultAuthNamespace
		const clusterRoleName = "vault-auth-cluster-role"
		const clusterRoleBindingName = "vault-auth-binding-vault-auth"

		AfterEach(func() {
			for _, obj := range []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleBindingName}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}},
			} {
				err := k8sClient.Delete(ctx, obj)
				if err != nil && !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}
		})

		It("should create ServiceAccount, token Secret, ClusterRole, and ClusterRoleBinding", func() {
			controllerReconciler := &VaultK8sConfigReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			Expect(controllerReconciler.ensureVaultAuthResources(ctx)).To(Succeed())

			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "vault-auth", Namespace: namespace}, sa)).To(Succeed())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "vault-auth", Namespace: namespace}, secret)).To(Succeed())
			Expect(secret.Type).To(Equal(corev1.SecretTypeServiceAccountToken))

			clusterRole := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterRoleName}, clusterRole)).To(Succeed())

			clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)).To(Succeed())
			Expect(clusterRoleBinding.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(clusterRoleBinding.RoleRef.Name).To(Equal(clusterRoleName))
			Expect(clusterRoleBinding.Subjects).To(ContainElement(rbacv1.Subject{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "vault-auth",
				Namespace: namespace,
			}))
		})
	})
})

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func removeString(items []string, target string) []string {
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		if item != target {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
