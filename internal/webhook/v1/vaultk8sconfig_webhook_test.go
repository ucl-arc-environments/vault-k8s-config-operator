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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "vault-k8s-config-operator/api/v1"
)

var _ = Describe("VaultK8sConfig Webhook", func() {
	var (
		obj       *v1.VaultK8sConfig
		oldObj    *v1.VaultK8sConfig
		validator VaultK8sConfigCustomValidator
	)

	BeforeEach(func() {
		obj = &v1.VaultK8sConfig{}
		oldObj = &v1.VaultK8sConfig{}
		validator = VaultK8sConfigCustomValidator{}
		Expect(validator).NotTo(BeNil(), "Expected validator to be initialized")
		Expect(oldObj).NotTo(BeNil(), "Expected oldObj to be initialized")
		Expect(obj).NotTo(BeNil(), "Expected obj to be initialized")
	})

	AfterEach(func() {
		// TODO (user): Add any teardown logic common to all tests
	})

	Context("When creating or updating VaultK8sConfig under Validating Webhook", func() {
		newConfig := func(name, namespace, mountPath string) *v1.VaultK8sConfig {
			return &v1.VaultK8sConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: v1.VaultK8sConfigSpec{
					VaultAddress: "https://vault.example.com",
					Auth: v1.VaultAuthSpec{
						TokenSecretRef: v1.SecretKeyRef{Name: "vault-token", Key: "token"},
					},
					Engine: v1.KubernetesSecretEngineSpec{
						MountPath:      mountPath,
						KubernetesHost: "https://kubernetes.default.svc",
					},
				},
			}
		}

		It("should reject create when another resource uses the same mountPath", func() {
			scheme := runtime.NewScheme()
			Expect(v1.AddToScheme(scheme)).To(Succeed())

			existing := newConfig("existing", "default", "kubernetes")
			validator = VaultK8sConfigCustomValidator{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build(),
			}

			obj = newConfig("candidate", "other", "/kubernetes/")
			_, err := validator.ValidateCreate(context.Background(), obj)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("duplicates mountPath"))
		})

		It("should allow create when mountPath is different", func() {
			scheme := runtime.NewScheme()
			Expect(v1.AddToScheme(scheme)).To(Succeed())

			existing := newConfig("existing", "default", "kubernetes")
			validator = VaultK8sConfigCustomValidator{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build(),
			}

			obj = newConfig("candidate", "other", "kubernetes-alt")
			_, err := validator.ValidateCreate(context.Background(), obj)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow update of the same resource", func() {
			scheme := runtime.NewScheme()
			Expect(v1.AddToScheme(scheme)).To(Succeed())

			existing := newConfig("existing", "default", "kubernetes")
			validator = VaultK8sConfigCustomValidator{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build(),
			}

			oldObj = newConfig("existing", "default", "kubernetes")
			obj = newConfig("existing", "default", "/kubernetes/")
			_, err := validator.ValidateUpdate(context.Background(), oldObj, obj)
			Expect(err).NotTo(HaveOccurred())
		})
	})

})
