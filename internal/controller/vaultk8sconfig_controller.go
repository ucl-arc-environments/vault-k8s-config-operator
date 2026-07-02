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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v1 "vault-k8s-config-operator/api/v1"
)

const (
	defaultRequeueDelay           = time.Minute
	successRequeueDelay           = 5 * time.Minute
	defaultClusterJWTSecretKey    = "token"
	defaultClusterCACertSecretKey = "ca.crt"
	vaultClientRequestTimeout     = 30 * time.Second
	vaultOperationMaxAttempts     = 3
	vaultOperationBaseBackoff     = time.Second

	conditionTypeReady         = "Ready"
	conditionReasonReconciling = "Reconciling"
	conditionReasonReady       = "Configured"
	conditionReasonFailed      = "ReconcileFailed"

	vaultAuthNamespace          = "vault-auth"
	vaultAuthServiceAccountName = "vault-auth"
	vaultAuthSecretName         = "vault-auth"
	vaultAuthClusterRoleName    = "vault-auth-cluster-role"
	vaultAuthFinalizer          = "environments.arc.ucl/finalizer"

	operatorManagedByLabelKey   = "app.kubernetes.io/managed-by"
	operatorManagedByLabelValue = "vault-k8s-config-operator"
)

type vaultSecretEngineInterface interface {
	VerifyKubernetesEngineMount(ctx context.Context, mountPath string) error
	ReadKubernetesSecretEngineConfig(ctx context.Context, mountPath string) (map[string]any, error)
	WriteKubernetesSecretEngineConfig(mountPath string, kubernetesHost string, jwt string, caCert string) error
	CloseIdleConnections()
}

type vaultSecretEngineClient struct {
	client     *vaultapi.Client
	httpClient *http.Client
}

var newVaultSecretEngineClient = func(cfg VaultSecretEngineConfig) (vaultSecretEngineInterface, error) {
	clientCfg := vaultapi.DefaultConfig()
	clientCfg.Address = cfg.Address
	clientCfg.Timeout = vaultClientRequestTimeout

	vaultClient, err := vaultapi.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	if cfg.Namespace != "" {
		vaultClient.SetNamespace(cfg.Namespace)
	}

	// Authenticate using either token or AppRole
	if cfg.Token != "" {
		// Direct token authentication
		vaultClient.SetToken(cfg.Token)
	} else if cfg.AppRoleRoleID != "" && cfg.AppRoleSecretID != "" {
		// AppRole authentication using the Logical API
		mountPath := cfg.AppRoleMountPath
		if mountPath == "" {
			mountPath = "approle"
		}
		trimmedMountPath := strings.Trim(mountPath, "/")
		authPath := fmt.Sprintf("auth/%s/login", trimmedMountPath)

		var resp *vaultapi.Secret
		// Use a child context with its own timeout to avoid blocking indefinitely on retries.
		// Account for: 3 attempts × 30s timeout + 1s + 2s backoff + overhead = ~3 minutes
		retryCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		err = withRetry(retryCtx, fmt.Sprintf("authenticate with AppRole using %q", authPath), func() error {
			attemptCtx, cancel := context.WithTimeout(context.Background(), vaultClientRequestTimeout)
			defer cancel()

			attemptResp, attemptErr := vaultClient.Logical().WriteWithContext(attemptCtx, authPath, map[string]any{
				"role_id":   cfg.AppRoleRoleID,
				"secret_id": cfg.AppRoleSecretID,
			})
			if attemptErr != nil {
				return attemptErr
			}

			resp = attemptResp
			return nil
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("failed to authenticate with AppRole: timeout after %s calling %q on %q: %w", vaultClientRequestTimeout, authPath, cfg.Address, err)
			}
			return nil, fmt.Errorf("failed to authenticate with AppRole calling %q on %q: %w", authPath, cfg.Address, err)
		}

		if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
			return nil, fmt.Errorf("no token returned from AppRole login")
		}

		vaultClient.SetToken(resp.Auth.ClientToken)
	} else {
		return nil, fmt.Errorf("neither token nor AppRole credentials provided")
	}

	return &vaultSecretEngineClient{client: vaultClient, httpClient: clientCfg.HttpClient}, nil
}

// VaultSecretEngineConfig holds all values required to configure the Vault Kubernetes secret engine.
type VaultSecretEngineConfig struct {
	Address          string
	Namespace        string
	Token            string // Token for direct token authentication
	AppRoleRoleID    string // AppRole role_id for AppRole authentication
	AppRoleSecretID  string // AppRole secret_id for AppRole authentication
	AppRoleMountPath string // Mount path for AppRole auth method
	MountPath        string
	KubernetesHost   string
	JWT              string
	CACert           string
}

// VaultK8sConfigReconciler reconciles a VaultK8sConfig object
type VaultK8sConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ConfigureSecretEngine    func(ctx context.Context, cfg VaultSecretEngineConfig) error
	EnsureVaultAuthResources func(ctx context.Context) error
}

// +kubebuilder:rbac:groups=environments.arc.ucl,resources=vaultk8sconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=environments.arc.ucl,resources=vaultk8sconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=environments.arc.ucl,resources=vaultk8sconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;delete;bind;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultK8sConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/reconcile
func (r *VaultK8sConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("vaultK8sConfig", req.String())
	log.Info("Starting reconciliation")

	resource := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		log.Info("Reconciling deletion")
		if err := r.reconcileDelete(ctx, resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(resource, vaultAuthFinalizer) {
		updated := resource.DeepCopy()
		controllerutil.AddFinalizer(updated, vaultAuthFinalizer)
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, err
		}
		resource = updated
	}

	if err := r.markReconciling(ctx, resource); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Building Vault configuration")
	vaultConfig, err := r.buildVaultSecretEngineConfig(ctx, resource)
	if err != nil {
		log.Error(err, "Failed to build Vault configuration inputs")
		if markErr := r.markFailed(ctx, resource, err); markErr != nil {
			return ctrl.Result{}, markErr
		}
		return ctrl.Result{RequeueAfter: defaultRequeueDelay}, nil
	}

	configure := r.ConfigureSecretEngine
	if configure == nil {
		// Not testing: use the real configure function that interacts with Vault.
		configure = configureVaultSecretEngine
	}

	log.Info("Configuring Vault Kubernetes secret engine", "mountPath", vaultConfig.MountPath, "vaultAddress", vaultConfig.Address)
	if err := configure(ctx, vaultConfig); err != nil {
		log.Error(err, "Failed to configure Vault Kubernetes secret engine", "mountPath", vaultConfig.MountPath, "vaultAddress", vaultConfig.Address)
		if markErr := r.markFailed(ctx, resource, err); markErr != nil {
			log.Error(markErr, "Failed to mark resource as failed - returning error to trigger requeue")
			return ctrl.Result{}, markErr
		}
		log.Info("Requeuing reconciliation after failure", "nextRetryAfter", defaultRequeueDelay)
		return ctrl.Result{RequeueAfter: defaultRequeueDelay}, nil
	}

	log.Info("Successfully configured Vault Kubernetes secret engine", "mountPath", vaultConfig.MountPath)
	if err := r.markReady(ctx, resource); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: successRequeueDelay}, nil
}

func (r *VaultK8sConfigReconciler) reconcileDelete(ctx context.Context, resource *v1.VaultK8sConfig) error {
	if !controllerutil.ContainsFinalizer(resource, vaultAuthFinalizer) {
		return nil
	}

	if resource.Spec.Engine.ClusterCredentialsSecretRef == nil {
		if err := r.cleanupVaultAuthResourcesIfUnused(ctx, resource); err != nil {
			return err
		}
	}

	updated := resource.DeepCopy()
	controllerutil.RemoveFinalizer(updated, vaultAuthFinalizer)
	return r.Update(ctx, updated)
}

func (r *VaultK8sConfigReconciler) cleanupVaultAuthResourcesIfUnused(ctx context.Context, current *v1.VaultK8sConfig) error {
	log := logf.FromContext(ctx)

	list := &v1.VaultK8sConfigList{}
	if err := r.List(ctx, list); err != nil {
		return fmt.Errorf("failed to list VaultK8sConfig resources for cleanup: %w", err)
	}

	for i := range list.Items {
		item := &list.Items[i]
		if item.Namespace == current.Namespace && item.Name == current.Name {
			continue
		}
		if item.DeletionTimestamp.IsZero() && item.Spec.Engine.ClusterCredentialsSecretRef == nil {
			return nil
		}
	}

	// Check the Namespace first. Only delete namespace-scoped resources (Secret, ServiceAccount,
	// and the Namespace itself) when the Namespace carries the operator-managed label, to avoid
	// touching a pre-existing "vault-auth" namespace that belongs to something else.
	ns := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: vaultAuthNamespace}, ns); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Namespace %q: %w", vaultAuthNamespace, err)
		}
		// Already absent; no namespace-scoped resources to clean up.
	} else if !isManagedByOperator(ns.Labels) {
		log.Info("Skipping cleanup of Namespace not managed by this operator", "name", vaultAuthNamespace)
	} else {
		for _, obj := range []client.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthSecretName, Namespace: vaultAuthNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthServiceAccountName, Namespace: vaultAuthNamespace}},
			ns,
		} {
			if err := r.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to cleanup %T %q: %w", obj, obj.GetName(), err)
			}
		}
	}

	// Cluster-scoped resources: fetch each and verify the managed-by label before deleting,
	// to avoid removing ClusterRole/ClusterRoleBinding that weren't created by this operator.
	clusterRoleBindingName := fmt.Sprintf("%s-binding-%s", vaultAuthServiceAccountName, vaultAuthNamespace)
	type clusterScopedObj struct {
		obj  client.Object
		name string
	}
	for _, item := range []clusterScopedObj{
		{&rbacv1.ClusterRoleBinding{}, clusterRoleBindingName},
		{&rbacv1.ClusterRole{}, vaultAuthClusterRoleName},
	} {
		if err := r.Get(ctx, types.NamespacedName{Name: item.name}, item.obj); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to get %T %q: %w", item.obj, item.name, err)
			}
			continue
		}
		if !isManagedByOperator(item.obj.GetLabels()) {
			log.Info("Skipping cleanup of resource not managed by this operator", "kind", fmt.Sprintf("%T", item.obj), "name", item.name)
			continue
		}
		if err := r.Delete(ctx, item.obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to cleanup %T %q: %w", item.obj, item.name, err)
		}
	}

	return nil
}

func isManagedByOperator(labels map[string]string) bool {
	return labels[operatorManagedByLabelKey] == operatorManagedByLabelValue
}

func (r *VaultK8sConfigReconciler) buildVaultSecretEngineConfig(
	ctx context.Context,
	resource *v1.VaultK8sConfig,
) (VaultSecretEngineConfig, error) {
	useManagedClusterCredentials := false

	// Extract Vault authentication credentials (token or AppRole)
	var vaultToken, appRoleRoleID, appRoleSecretID, appRoleMountPath string

	if resource.Spec.Auth.TokenSecretRef != nil {
		// Token authentication
		token, err := r.getSecretValue(
			ctx,
			resource.Namespace,
			resource.Spec.Auth.TokenSecretRef.Name,
			resource.Spec.Auth.TokenSecretRef.Key,
		)
		if err != nil {
			return VaultSecretEngineConfig{}, fmt.Errorf("vault token secret reference is invalid: %w", err)
		}
		vaultToken = token
	} else if resource.Spec.Auth.AppRoleAuth != nil {
		// AppRole authentication
		roleID := resource.Spec.Auth.AppRoleAuth.RoleId
		if roleID == "" {
			return VaultSecretEngineConfig{}, fmt.Errorf("AppRole role_id is required")
		}

		secretID, err := r.getSecretValue(
			ctx,
			resource.Namespace,
			resource.Spec.Auth.AppRoleAuth.SecretIdSecretRef.Name,
			resource.Spec.Auth.AppRoleAuth.SecretIdSecretRef.Key,
		)
		if err != nil {
			return VaultSecretEngineConfig{}, fmt.Errorf("AppRole secret_id secret reference is invalid: %w", err)
		}

		appRoleRoleID = roleID
		appRoleSecretID = secretID
		appRoleMountPath = resource.Spec.Auth.AppRoleAuth.MountPath
		if appRoleMountPath == "" {
			appRoleMountPath = "approle"
		}
	} else {
		return VaultSecretEngineConfig{}, fmt.Errorf("either tokenSecretRef or AppRoleAuth must be specified in auth")
	}

	jwtKey := defaultClusterJWTSecretKey
	caCertKey := defaultClusterCACertSecretKey
	clusterSecretName := vaultAuthSecretName
	clusterSecretNamespace := vaultAuthNamespace

	if ref := resource.Spec.Engine.ClusterCredentialsSecretRef; ref != nil {
		// Explicit secret reference provided.
		clusterSecretName = ref.Name
		if ref.Namespace == "" {
			return VaultSecretEngineConfig{}, fmt.Errorf("cluster credentials secret namespace is required when clusterCredentialsSecretRef is set")
		}
		clusterSecretNamespace = ref.Namespace
		if ref.JWTKey != "" {
			jwtKey = ref.JWTKey
		}
		if ref.CACertKey != "" {
			caCertKey = ref.CACertKey
		}
	} else {
		useManagedClusterCredentials = true
		// No reference provided: provision shared vault-auth resources in the fixed vault-auth namespace.
		provision := r.EnsureVaultAuthResources
		if provision == nil {
			// Not testing: use the real provision function that creates vault-auth resources.
			provision = r.ensureVaultAuthResources
		}
		if err := provision(ctx); err != nil {
			return VaultSecretEngineConfig{}, fmt.Errorf("failed to provision vault-auth resources: %w", err)
		}
	}

	jwt, err := r.getSecretValue(ctx, clusterSecretNamespace, clusterSecretName, jwtKey)
	if err != nil {
		if useManagedClusterCredentials {
			jwtFromTokenRequest, tokenErr := r.getServiceAccountToken(
				ctx,
				vaultAuthNamespace,
				vaultAuthServiceAccountName,
			)
			if tokenErr == nil {
				jwt = jwtFromTokenRequest
			} else {
				return VaultSecretEngineConfig{}, fmt.Errorf(
					"cluster credentials JWT reference is invalid: %w; token request fallback failed: %v",
					err,
					tokenErr,
				)
			}
		} else {
			return VaultSecretEngineConfig{}, fmt.Errorf("cluster credentials JWT reference is invalid: %w", err)
		}
	}

	caCert, err := r.getSecretValue(ctx, clusterSecretNamespace, clusterSecretName, caCertKey)
	if err != nil {
		if useManagedClusterCredentials {
			caFromConfigMap, caErr := r.getKubeRootCACert(ctx, vaultAuthNamespace)
			if caErr == nil {
				caCert = caFromConfigMap
			} else {
				return VaultSecretEngineConfig{}, fmt.Errorf(
					"cluster credentials CA certificate reference is invalid: %w; kube-root-ca fallback failed: %v",
					err,
					caErr,
				)
			}
		} else {
			return VaultSecretEngineConfig{}, fmt.Errorf("cluster credentials CA certificate reference is invalid: %w", err)
		}
	}

	return VaultSecretEngineConfig{
		Address:          resource.Spec.VaultAddress,
		Namespace:        resource.Spec.VaultNamespace,
		Token:            vaultToken,
		AppRoleRoleID:    appRoleRoleID,
		AppRoleSecretID:  appRoleSecretID,
		AppRoleMountPath: appRoleMountPath,
		MountPath:        resource.Spec.Engine.MountPath,
		KubernetesHost:   resource.Spec.Engine.KubernetesHost,
		JWT:              jwt,
		CACert:           caCert,
	}, nil
}

func (r *VaultK8sConfigReconciler) ensureVaultAuthResources(ctx context.Context) error {
	log := logf.FromContext(ctx)

	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: vaultAuthNamespace}, namespace); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Namespace %q: %w", vaultAuthNamespace, err)
		}
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   vaultAuthNamespace,
				Labels: map[string]string{operatorManagedByLabelKey: operatorManagedByLabelValue},
			},
		}
		if err := r.Create(ctx, namespace); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create Namespace %q: %w", vaultAuthNamespace, err)
		}
		log.V(1).Info("Created Namespace", "name", vaultAuthNamespace)
	}

	clusterRole := &rbacv1.ClusterRole{}
	if err := r.Get(ctx, types.NamespacedName{Name: vaultAuthClusterRoleName}, clusterRole); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get ClusterRole %q: %w", vaultAuthClusterRoleName, err)
		}
		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   vaultAuthClusterRoleName,
				Labels: map[string]string{operatorManagedByLabelKey: operatorManagedByLabelValue},
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"namespaces"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts", "serviceaccounts/token"},
					Verbs:     []string{"create", "get", "update", "delete"},
				},
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"rolebindings", "clusterrolebindings"},
					Verbs:     []string{"create", "update", "delete"},
				},
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"roles", "clusterroles"},
					Verbs:     []string{"bind", "escalate", "get", "create", "update", "delete"},
				},
			},
		}
		if err := r.Create(ctx, clusterRole); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create ClusterRole %q: %w", vaultAuthClusterRoleName, err)
		}
		log.V(1).Info("Created ClusterRole", "name", vaultAuthClusterRoleName)
	}

	clusterRoleBindingName := fmt.Sprintf("%s-binding-%s", vaultAuthServiceAccountName, vaultAuthNamespace)
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	if err := r.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get ClusterRoleBinding %q: %w", clusterRoleBindingName, err)
		}
		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   clusterRoleBindingName,
				Labels: map[string]string{operatorManagedByLabelKey: operatorManagedByLabelValue},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     vaultAuthClusterRoleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      vaultAuthServiceAccountName,
				Namespace: vaultAuthNamespace,
			}},
		}
		if err := r.Create(ctx, clusterRoleBinding); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create ClusterRoleBinding %q: %w", clusterRoleBindingName, err)
		}
		log.V(1).Info("Created ClusterRoleBinding", "name", clusterRoleBindingName, "namespace", vaultAuthNamespace)
	}

	sa := &corev1.ServiceAccount{}
	if err := r.Get(ctx, types.NamespacedName{Name: vaultAuthServiceAccountName, Namespace: vaultAuthNamespace}, sa); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get ServiceAccount %q: %w", vaultAuthServiceAccountName, err)
		}
		sa = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vaultAuthServiceAccountName,
				Namespace: vaultAuthNamespace,
				Labels:    map[string]string{operatorManagedByLabelKey: operatorManagedByLabelValue},
			},
		}
		if err := r.Create(ctx, sa); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create ServiceAccount %q: %w", vaultAuthServiceAccountName, err)
		}
		log.V(1).Info("Created ServiceAccount", "name", vaultAuthServiceAccountName, "namespace", vaultAuthNamespace)
	}

	tokenSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: vaultAuthSecretName, Namespace: vaultAuthNamespace}, tokenSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Secret %q: %w", vaultAuthSecretName, err)
		}
		tokenSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vaultAuthSecretName,
				Namespace: vaultAuthNamespace,
				Annotations: map[string]string{
					"kubernetes.io/service-account.name": vaultAuthServiceAccountName,
				},
				Labels: map[string]string{operatorManagedByLabelKey: operatorManagedByLabelValue},
			},
			Type: corev1.SecretTypeServiceAccountToken,
		}
		if err := r.Create(ctx, tokenSecret); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create service account token Secret %q: %w", vaultAuthSecretName, err)
		}
		log.V(1).Info("Created service account token Secret", "name", vaultAuthSecretName, "namespace", vaultAuthNamespace)
	}

	return nil
}

func (r *VaultK8sConfigReconciler) getSecretValue(
	ctx context.Context,
	namespace string,
	secretName string,
	key string,
) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return "", err
	}

	value, found := secret.Data[key]
	if !found {
		return "", fmt.Errorf("secret %s/%s does not contain key %q", namespace, secretName, key)
	}

	if len(value) == 0 {
		return "", fmt.Errorf("secret %s/%s key %q is empty", namespace, secretName, key)
	}

	return string(value), nil
}

func (r *VaultK8sConfigReconciler) getServiceAccountToken(
	ctx context.Context,
	namespace string,
	serviceAccountName string,
) (string, error) {
	tokenReq := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences: []string{"https://kubernetes.default.svc"},
		},
	}

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: serviceAccountName, Namespace: namespace}}
	if err := r.SubResource("token").Create(ctx, sa, tokenReq); err != nil {
		return "", err
	}

	if tokenReq.Status.Token == "" {
		return "", fmt.Errorf("empty token in token request response")
	}

	return tokenReq.Status.Token, nil
}

func (r *VaultK8sConfigReconciler) getKubeRootCACert(ctx context.Context, namespace string) (string, error) {
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: "kube-root-ca.crt", Namespace: namespace}, configMap); err != nil {
		return "", err
	}

	caCert, found := configMap.Data["ca.crt"]
	if !found {
		return "", fmt.Errorf("configmap %s/%s does not contain key %q", namespace, "kube-root-ca.crt", "ca.crt")
	}

	if caCert == "" {
		return "", fmt.Errorf("configmap %s/%s key %q is empty", namespace, "kube-root-ca.crt", "ca.crt")
	}

	return caCert, nil
}

func configureVaultSecretEngine(ctx context.Context, cfg VaultSecretEngineConfig) error {
	log := logf.FromContext(ctx)
	vaultClient, err := newVaultSecretEngineClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Vault client for %q: %w", cfg.Address, err)
	}
	// Each reconcile creates a new client and HTTP transport. Explicitly close idle
	// connections so the transport and its goroutines can be GC'd immediately.
	defer func() {
		vaultClient.CloseIdleConnections()
		log.V(2).Info("Closed idle Vault client connections")
	}()

	log.V(1).Info("Verifying Kubernetes secret engine mount", "mountPath", cfg.MountPath)
	if err := withRetry(ctx, "verify Kubernetes secret engine mount", func() error {
		return vaultClient.VerifyKubernetesEngineMount(ctx, cfg.MountPath)
	}); err != nil {
		return fmt.Errorf("failed to verify mount %q at %q: %w", cfg.MountPath, cfg.Address, err)
	}

	driftDetected := false
	if currentConfig, err := vaultClient.ReadKubernetesSecretEngineConfig(ctx, cfg.MountPath); err == nil {
		driftDetected = hasKubernetesSecretEngineDrift(currentConfig, cfg)
	} else {
		log.V(1).Info("Could not read current config (may be uninitialized)", "error", err)
	}

	log.V(1).Info("Writing Kubernetes secret engine configuration", "mountPath", cfg.MountPath)
	if err := withRetry(ctx, "write Kubernetes secret engine config", func() error {
		return vaultClient.WriteKubernetesSecretEngineConfig(cfg.MountPath, cfg.KubernetesHost, cfg.JWT, cfg.CACert)
	}); err != nil {
		return fmt.Errorf("failed to write Kubernetes secret engine config to %q at %q: %w", cfg.MountPath, cfg.Address, err)
	}

	if driftDetected {
		log.Info("Corrected Vault Kubernetes secret engine drift", "mountPath", cfg.MountPath)
	}

	log.V(1).Info("Successfully configured Vault Kubernetes secret engine", "mountPath", cfg.MountPath)
	return nil
}

func (c *vaultSecretEngineClient) VerifyKubernetesEngineMount(ctx context.Context, mountPath string) error {
	return verifyKubernetesEngineMount(ctx, c.client, mountPath)
}

func (c *vaultSecretEngineClient) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func (c *vaultSecretEngineClient) ReadKubernetesSecretEngineConfig(
	ctx context.Context,
	mountPath string,
) (map[string]any, error) {
	secret, err := c.client.Logical().ReadWithContext(ctx, strings.Trim(mountPath, "/")+"/config")
	if err != nil {
		return nil, fmt.Errorf("failed to read Kubernetes secret engine config: %w", err)
	}
	if secret == nil {
		return map[string]any{}, nil
	}

	return secret.Data, nil
}

func (c *vaultSecretEngineClient) WriteKubernetesSecretEngineConfig(
	mountPath string,
	kubernetesHost string,
	jwt string,
	caCert string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), vaultClientRequestTimeout)
	defer cancel()
	if _, err := c.client.Logical().WriteWithContext(ctx, strings.Trim(mountPath, "/")+"/config", map[string]any{
		"kubernetes_host":     kubernetesHost,
		"service_account_jwt": jwt,
		"kubernetes_ca_cert":  caCert,
	}); err != nil {
		return fmt.Errorf("failed to write Kubernetes secret engine config: %w", err)
	}

	return nil
}

func verifyKubernetesEngineMount(ctx context.Context, vaultClient *vaultapi.Client, mountPath string) error {
	normalized := strings.Trim(mountPath, "/")
	resp, err := vaultClient.Logical().ReadRawWithContext(ctx, normalized+"/config")
	if resp != nil {
		defer func() {
			_ = resp.Body.Close() // Ignore close errors on read
		}()
	}
	if err != nil {
		var responseErr *vaultapi.ResponseError
		if errors.As(err, &responseErr) {
			if responseErr.StatusCode == http.StatusNotFound {
				return fmt.Errorf("kubernetes secret engine mount %q not found; ensure it is pre-configured in Vault", mountPath)
			}
			// A 403 means the mount exists but the token lacks read on the config path.
			// This is sufficient to confirm the mount is present; proceed.
			if responseErr.StatusCode == http.StatusForbidden {
				return nil
			}
		}
		return fmt.Errorf("failed to find Vault mount %q: %w", mountPath, err)
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("kubernetes secret engine mount %q not found; ensure it is pre-configured in Vault", mountPath)
	}

	return nil
}

func hasKubernetesSecretEngineDrift(current map[string]any, desired VaultSecretEngineConfig) bool {
	if current == nil {
		return true
	}

	currentHost, ok := getStringValue(current, "kubernetes_host")
	if !ok || currentHost != desired.KubernetesHost {
		return true
	}

	currentCACert, ok := getStringValue(current, "kubernetes_ca_cert")
	if !ok || currentCACert != desired.CACert {
		return true
	}

	// Only compare it when JWT is present.
	if currentJWT, ok := getStringValue(current, "service_account_jwt"); ok && currentJWT != desired.JWT {
		return true
	}

	return false
}

func getStringValue(values map[string]any, key string) (string, bool) {
	raw, found := values[key]
	if !found {
		return "", false
	}

	value, ok := raw.(string)
	if !ok {
		return "", false
	}

	return value, true
}

func withRetry(ctx context.Context, operation string, fn func() error) error {
	var lastErr error

	for attempt := 1; attempt <= vaultOperationMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s canceled: %w", operation, err)
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		if !isRetryableVaultError(lastErr) {
			return fmt.Errorf("%s failed with non-retryable error: %w", operation, lastErr)
		}

		if attempt == vaultOperationMaxAttempts {
			break
		}

		backoff := time.Duration(attempt) * vaultOperationBaseBackoff
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s canceled while retrying: %w", operation, ctx.Err())
		case <-time.After(backoff):
		}
	}

	return fmt.Errorf("%s failed after %d attempts: %w", operation, vaultOperationMaxAttempts, lastErr)
}

func isRetryableVaultError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) {
		return false
	}

	// Treat deadline exceeded (timeouts) as retryable since Vault may just be slow
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var responseErr *vaultapi.ResponseError
	if errors.As(err, &responseErr) {
		if responseErr.StatusCode == http.StatusTooManyRequests || responseErr.StatusCode == http.StatusRequestTimeout {
			return true
		}
		return responseErr.StatusCode >= http.StatusInternalServerError
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	return false
}

func (r *VaultK8sConfigReconciler) markReconciling(
	ctx context.Context,
	resource *v1.VaultK8sConfig,
) error {
	latest := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, latest); err != nil {
		return err
	}

	readyCondition := findCondition(latest.Status.Conditions, conditionTypeReady)
	if readyCondition != nil &&
		readyCondition.Status == metav1.ConditionTrue &&
		readyCondition.Reason == conditionReasonReady &&
		readyCondition.ObservedGeneration == latest.Generation {
		return nil
	}

	base := latest.DeepCopy()
	latest.Status.ObservedGeneration = latest.Generation
	latest.Status.Conditions = setCondition(latest.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             conditionReasonReconciling,
		Message:            "Reconciling desired Vault Kubernetes secret engine configuration",
		ObservedGeneration: latest.Generation,
		LastTransitionTime: metav1.Now(),
	})

	return r.Status().Patch(ctx, latest, client.MergeFrom(base))
}

func (r *VaultK8sConfigReconciler) markReady(
	ctx context.Context,
	resource *v1.VaultK8sConfig,
) error {
	log := logf.FromContext(ctx)
	latest := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, latest); err != nil {
		return err
	}

	readyCondition := findCondition(latest.Status.Conditions, conditionTypeReady)
	shouldLogReady := readyCondition == nil ||
		readyCondition.Status != metav1.ConditionTrue ||
		readyCondition.ObservedGeneration != latest.Generation ||
		readyCondition.Reason != conditionReasonReady

	base := latest.DeepCopy()
	latest.Status.ObservedGeneration = latest.Generation
	latest.Status.Conditions = setCondition(latest.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             conditionReasonReady,
		Message:            "Vault Kubernetes secret engine configuration applied",
		ObservedGeneration: latest.Generation,
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Patch(ctx, latest, client.MergeFrom(base)); err != nil {
		return err
	}

	if shouldLogReady {
		log.Info("VaultK8sConfig became Ready", "name", latest.Name, "namespace", latest.Namespace)
	}

	return nil
}

func (r *VaultK8sConfigReconciler) markFailed(
	ctx context.Context,
	resource *v1.VaultK8sConfig,
	reconcileErr error,
) error {
	log := logf.FromContext(ctx)
	log.Info("Attempting to mark resource as failed")

	latest := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, latest); err != nil {
		log.Error(err, "Failed to get latest resource for status update")
		return err
	}

	base := latest.DeepCopy()
	latest.Status.ObservedGeneration = latest.Generation
	latest.Status.Conditions = setCondition(latest.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             conditionReasonFailed,
		Message:            reconcileErr.Error(),
		ObservedGeneration: latest.Generation,
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Patch(ctx, latest, client.MergeFrom(base)); err != nil {
		log.Error(err, "Failed to patch status after reconciliation failure")
		return err
	}

	log.Info("Successfully marked resource as failed")
	return nil
}

func setCondition(conditions []metav1.Condition, next metav1.Condition) []metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == next.Type {
			// Only advance LastTransitionTime when Status actually changes.
			// Preserving it on same-Status updates prevents spurious watch events
			// that would otherwise re-enqueue a reconcile on every status patch.
			if conditions[i].Status == next.Status {
				next.LastTransitionTime = conditions[i].LastTransitionTime
			}
			conditions[i] = next
			return conditions
		}
	}

	return append(conditions, next)
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultK8sConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.VaultK8sConfig{}).
		Named("vaultk8sconfig").
		Complete(r)
}
