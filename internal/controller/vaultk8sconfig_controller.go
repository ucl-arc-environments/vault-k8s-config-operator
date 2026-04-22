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
	defaultClusterJWTSecretKey    = "token"
	defaultClusterCACertSecretKey = "ca.crt"
	vaultClientRequestTimeout     = 10 * time.Second
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
)

type vaultSecretEngineInterface interface {
	VerifyKubernetesEngineMount(ctx context.Context, mountPath string) error
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

	vaultClient.SetToken(cfg.Token)
	if cfg.Namespace != "" {
		vaultClient.SetNamespace(cfg.Namespace)
	}

	return &vaultSecretEngineClient{client: vaultClient, httpClient: clientCfg.HttpClient}, nil
}

// VaultSecretEngineConfig holds all values required to configure the Vault Kubernetes secret engine.
type VaultSecretEngineConfig struct {
	Address        string
	Namespace      string
	Token          string
	MountPath      string
	KubernetesHost string
	JWT            string
	CACert         string
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
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;bind;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create

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

	resource := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
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

	if err := configure(ctx, vaultConfig); err != nil {
		log.Error(err, "Failed to configure Vault Kubernetes secret engine", "mountPath", vaultConfig.MountPath)
		if markErr := r.markFailed(ctx, resource, err); markErr != nil {
			return ctrl.Result{}, markErr
		}
		return ctrl.Result{RequeueAfter: defaultRequeueDelay}, nil
	}

	if err := r.markReady(ctx, resource); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
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

	clusterRoleBindingName := fmt.Sprintf("%s-binding-%s", vaultAuthServiceAccountName, vaultAuthNamespace)
	for _, obj := range []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthSecretName, Namespace: vaultAuthNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthServiceAccountName, Namespace: vaultAuthNamespace}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleBindingName}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthClusterRoleName}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: vaultAuthNamespace}},
	} {
		if err := r.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to cleanup resource %T: %w", obj, err)
		}
	}

	return nil
}

func (r *VaultK8sConfigReconciler) buildVaultSecretEngineConfig(
	ctx context.Context,
	resource *v1.VaultK8sConfig,
) (VaultSecretEngineConfig, error) {
	useManagedClusterCredentials := false

	vaultToken, err := r.getSecretValue(
		ctx,
		resource.Namespace,
		resource.Spec.Auth.TokenSecretRef.Name,
		resource.Spec.Auth.TokenSecretRef.Key,
	)
	if err != nil {
		return VaultSecretEngineConfig{}, fmt.Errorf("vault token secret reference is invalid: %w", err)
	}

	jwtKey := defaultClusterJWTSecretKey
	caCertKey := defaultClusterCACertSecretKey
	clusterSecretName := vaultAuthSecretName
	clusterSecretNamespace := vaultAuthNamespace

	if ref := resource.Spec.Engine.ClusterCredentialsSecretRef; ref != nil {
		// Explicit secret reference provided.
		clusterSecretName = ref.Name
		if ref.Namespace != "" {
			clusterSecretNamespace = ref.Namespace
		}
		if ref.JWTKey != "" {
			jwtKey = ref.JWTKey
		}
		if ref.CACertKey != "" {
			caCertKey = ref.CACertKey
		}
	} else {
		useManagedClusterCredentials = true
		// No reference provided: provision vault-auth resources in the CR's namespace.
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
		Address:        resource.Spec.VaultAddress,
		Namespace:      resource.Spec.VaultNamespace,
		Token:          vaultToken,
		MountPath:      resource.Spec.Engine.MountPath,
		KubernetesHost: resource.Spec.Engine.KubernetesHost,
		JWT:            jwt,
		CACert:         caCert,
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
				Labels: map[string]string{"app.kubernetes.io/managed-by": "vault-k8s-config-operator"},
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
				Labels: map[string]string{"app.kubernetes.io/managed-by": "vault-k8s-config-operator"},
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
				Labels: map[string]string{"app.kubernetes.io/managed-by": "vault-k8s-config-operator"},
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
				Labels:    map[string]string{"app.kubernetes.io/managed-by": "vault-k8s-config-operator"},
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
				Labels: map[string]string{"app.kubernetes.io/managed-by": "vault-k8s-config-operator"},
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
	vaultClient, err := newVaultSecretEngineClient(cfg)
	if err != nil {
		return err
	}
	// Each reconcile creates a new client and HTTP transport. Explicitly close idle
	// connections so the transport and its goroutines can be GC'd immediately.
	defer vaultClient.CloseIdleConnections()

	if err := withRetry(ctx, "verify Kubernetes secret engine mount", func() error {
		return vaultClient.VerifyKubernetesEngineMount(ctx, cfg.MountPath)
	}); err != nil {
		return err
	}

	if err := withRetry(ctx, "write Kubernetes secret engine config", func() error {
		return vaultClient.WriteKubernetesSecretEngineConfig(cfg.MountPath, cfg.KubernetesHost, cfg.JWT, cfg.CACert)
	}); err != nil {
		return err
	}

	return nil
}

func (c *vaultSecretEngineClient) VerifyKubernetesEngineMount(ctx context.Context, mountPath string) error {
	return verifyKubernetesEngineMount(ctx, c.client, mountPath)
}

func (c *vaultSecretEngineClient) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func (c *vaultSecretEngineClient) WriteKubernetesSecretEngineConfig(
	mountPath string,
	kubernetesHost string,
	jwt string,
	caCert string,
) error {
	if _, err := c.client.Logical().Write(strings.Trim(mountPath, "/")+"/config", map[string]any{
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
	resp, err := vaultClient.Logical().ReadRawWithContext(ctx, normalized)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		var responseErr *vaultapi.ResponseError
		if errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound {
			return fmt.Errorf("Kubernetes secret engine mount %q not found; ensure it is pre-configured in Vault", mountPath)
		}
		return fmt.Errorf("failed to find Vault mount %q: %w", mountPath, err)
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("Kubernetes secret engine mount %q not found; ensure it is pre-configured in Vault", mountPath)
	}

	return nil
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

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
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
	latest := &v1.VaultK8sConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, latest); err != nil {
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

	return r.Status().Patch(ctx, latest, client.MergeFrom(base))
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
