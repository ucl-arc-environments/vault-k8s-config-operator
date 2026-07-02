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
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1 "vault-k8s-config-operator/api/v1"
)

// nolint:unused
// log is for logging in this package.
var vaultk8sconfiglog = logf.Log.WithName("vaultk8sconfig-resource")

// SetupVaultK8sConfigWebhookWithManager registers the webhook for VaultK8sConfig in the manager.
func SetupVaultK8sConfigWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1.VaultK8sConfig{}).
		WithValidator(&VaultK8sConfigCustomValidator{Client: mgr.GetAPIReader()}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-environments-arc-ucl-v1-vaultk8sconfig,mutating=false,failurePolicy=ignore,sideEffects=None,groups=environments.arc.ucl,resources=vaultk8sconfigs,verbs=create;update,versions=v1,name=vvaultk8sconfig-v1.kb.io,admissionReviewVersions=v1

// VaultK8sConfigCustomValidator struct is responsible for validating the VaultK8sConfig resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type VaultK8sConfigCustomValidator struct {
	Client client.Reader
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type VaultK8sConfig.
func (v *VaultK8sConfigCustomValidator) ValidateCreate(ctx context.Context, obj *v1.VaultK8sConfig) (admission.Warnings, error) {
	vaultk8sconfiglog.Info("Validation for VaultK8sConfig upon creation", "name", obj.GetName())

	return nil, v.validateUniqueMountPath(ctx, obj)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type VaultK8sConfig.
func (v *VaultK8sConfigCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *v1.VaultK8sConfig) (admission.Warnings, error) {
	vaultk8sconfiglog.Info("Validation for VaultK8sConfig upon update", "name", newObj.GetName())

	return nil, v.validateUniqueMountPath(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type VaultK8sConfig.
func (v *VaultK8sConfigCustomValidator) ValidateDelete(_ context.Context, obj *v1.VaultK8sConfig) (admission.Warnings, error) {
	vaultk8sconfiglog.Info("Validation for VaultK8sConfig upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}

func (v *VaultK8sConfigCustomValidator) validateUniqueMountPath(ctx context.Context, obj *v1.VaultK8sConfig) error {
	if v.Client == nil {
		return fmt.Errorf("webhook client is not configured")
	}

	targetMountPath := normalizedMountPath(obj.Spec.Engine.MountPath)
	var existing v1.VaultK8sConfigList
	if err := v.Client.List(ctx, &existing); err != nil {
		return fmt.Errorf("failed to list existing VaultK8sConfig resources: %w", err)
	}

	for i := range existing.Items {
		candidate := &existing.Items[i]
		if candidate.Namespace == obj.Namespace && candidate.Name == obj.Name {
			continue
		}

		if normalizedMountPath(candidate.Spec.Engine.MountPath) != targetMountPath {
			continue
		}

		return apierrors.NewInvalid(
			schema.GroupKind{Group: v1.GroupVersion.Group, Kind: "VaultK8sConfig"},
			obj.Name,
			field.ErrorList{
				field.Invalid(
					field.NewPath("spec", "engine", "mountPath"),
					obj.Spec.Engine.MountPath,
					fmt.Sprintf("duplicates mountPath of %s/%s", candidate.Namespace, candidate.Name),
				),
			},
		)
	}

	return nil
}

func normalizedMountPath(mountPath string) string {
	return strings.Trim(mountPath, "/")
}
