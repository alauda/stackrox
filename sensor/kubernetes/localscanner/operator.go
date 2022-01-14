package localscanner

import (
	"context"
	"crypto/x509"
	"math/rand"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/centralsensor"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stackrox/rox/sensor/common"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	issueCertificatesTimeout               = 2 * time.Minute
	fetchSecretsTimeout                    = 2 * time.Minute
	updateSecretsTimeout                   = 2 * time.Minute
	refreshSecretsMaxNumAttempts           = uint(5)
	refreshSecretAttemptWaitTime           = 5 * time.Minute
	refreshSecretAllAttemptsFailedWaitTime = 2 * time.Hour
	localScannerCredentialsSecretName      = "scanner-local-tls"
	localScannerDBCredentialsSecretName    = "scanner-db-local-tls"
)

var (
	log = logging.LoggerForModule()
)

// NewLocalScannerOperator creates a Sensor component that maintains the local Scanner TLS certificates
// up to date. FIXME rename?
func NewLocalScannerOperator(k8sClient kubernetes.Interface, sensorNamespace string) common.SensorComponent {
	return &localscannerOperatorImpl{
		sensorNamespace: sensorNamespace,
		secretsClient:   k8sClient.CoreV1().Secrets(sensorNamespace),
		ctx:             context.Background(),
		responsesC:      make(chan *central.MsgFromSensor),
	}
}

type localscannerOperatorImpl struct {
	sensorNamespace                      string
	secretsClient                        corev1.SecretInterface
	numLocalScannerSecretRefreshAttempts uint
	refreshTimer                         *time.Timer
	ctx                                  context.Context
	responsesC                           chan *central.MsgFromSensor
}

func (o *localscannerOperatorImpl) Start() error {
	log.Info("starting local scanner operator.")

	if err := o.scheduleLocalScannerSecretsRefresh(); err != nil {
		return errors.Wrap(err, "failure scheduling local scanner secrets refresh")
	}

	log.Info("local scanner operator started.")

	return nil
}

func (o *localscannerOperatorImpl) Stop(err error) {
	if o.refreshTimer != nil {
		o.refreshTimer.Stop()
	}
	log.Info("local scanner operator stopped.")
}

func (o *localscannerOperatorImpl) Capabilities() []centralsensor.SensorCapability {
	return []centralsensor.SensorCapability{centralsensor.LocalScannerCredentialsRefresh}
}

func (o *localscannerOperatorImpl) ProcessMessage(msg *central.MsgToSensor) error {
	switch m := msg.GetMsg().(type) {
	case *central.MsgToSensor_IssueLocalScannerCertsResponse:
		issueCertsResponse := m.IssueLocalScannerCertsResponse
		nextTimeToRefresh, refreshErr := o.refreshLocalScannerSecrets(issueCertsResponse)
		if refreshErr == nil {
			log.Infof("successfully refreshed local Scanner credential secrets %s and %s",
				localScannerCredentialsSecretName, localScannerDBCredentialsSecretName)
			o.numLocalScannerSecretRefreshAttempts = 0
			o.doScheduleLocalScannerSecretsRefresh(nextTimeToRefresh)
			return nil
		}
		// note centralReceiverImpl just logs the error
		err := errors.Wrapf(refreshErr, "attempt %d to refresh local Scanner credential secrets, will retry in %s",
			o.numLocalScannerSecretRefreshAttempts, refreshSecretAttemptWaitTime)
		o.numLocalScannerSecretRefreshAttempts++
		if o.numLocalScannerSecretRefreshAttempts <= refreshSecretsMaxNumAttempts {
			o.doScheduleLocalScannerSecretsRefresh(refreshSecretAttemptWaitTime)
		} else {
			err = errors.Wrapf(refreshErr, "Failed to refresh local Scanner credential secrets after %d attempts, "+
				"will wait %s and restart the retry cycle",
				refreshSecretsMaxNumAttempts, refreshSecretAllAttemptsFailedWaitTime)
			o.numLocalScannerSecretRefreshAttempts = 0
			o.doScheduleLocalScannerSecretsRefresh(refreshSecretAllAttemptsFailedWaitTime)
		}
		return err

	default:
		// FIXME return err
		return nil
	}
}

func (o *localscannerOperatorImpl) ResponsesC() <-chan *central.MsgFromSensor {
	return o.responsesC
}

func (o *localscannerOperatorImpl) scheduleLocalScannerSecretsRefresh() error {
	localScannerCredsSecret, localScannerDBCredsSecret, fetchErr := o.fetchLocalScannerSecrets()
	if k8sErrors.IsNotFound(fetchErr) {
		log.Warnf("some local scanner secret is missing, "+
			"operator will not maintain any local scanner secret fresh : %v", fetchErr)
		return nil
	}
	if fetchErr != nil {
		// FIXME wrap
		return fetchErr
	}

	// if certificates are already expired this refreshes immediately.
	o.doScheduleLocalScannerSecretsRefresh(getScannerSecretsDuration(localScannerCredsSecret, localScannerDBCredsSecret))
	return nil
}

func (o *localscannerOperatorImpl) doScheduleLocalScannerSecretsRefresh(timeToRefresh time.Duration) {
	log.Infof("local scanner certificates scheduled to be refreshed in %s", timeToRefresh)
	o.refreshTimer = time.AfterFunc(timeToRefresh, func() {
		if err := o.issueScannerCertificates(); err != nil {
			// FIXME log and treat as o.numLocalScannerSecretRefreshAttempts >= refreshSecretsMaxNumAttempts
			log.Error("FIXME")
		}
	})
}

func getScannerSecretsDuration(localScannerCredsSecret, localScannerDBCredsSecret *v1.Secret) time.Duration {
	scannerDuration := getScannerSecretDuration(localScannerCredsSecret)
	scannerDBDuration := getScannerSecretDuration(localScannerDBCredsSecret)
	if scannerDuration > scannerDBDuration {
		return scannerDBDuration
	}
	return scannerDuration
}

func getScannerSecretDurationFromCertificate(scannerCert *x509.Certificate) time.Duration {
	certValidityDurationSecs := scannerCert.NotAfter.Sub(scannerCert.NotBefore).Seconds()
	durationBeforeRenewalAttempt := time.Second *
		(time.Duration(certValidityDurationSecs/2) - time.Duration(rand.Intn(int(certValidityDurationSecs/10))))
	certRenewalTime := scannerCert.NotBefore.Add(durationBeforeRenewalAttempt)
	timeToRefresh := time.Until(certRenewalTime)
	if timeToRefresh.Seconds() <= 0 {
		// Certificate is already expired.
		return 0
	}
	return timeToRefresh
}

func getScannerSecretDuration(scannerSecret *v1.Secret) time.Duration {
	scannerCertBytes := scannerSecret.Data[mtls.ServiceCertFileName]
	scannerCert, err := helpers.ParseCertificatePEM(scannerCertBytes)
	if err != nil {
		// Note this also covers a secret with no certificates stored, which should be refreshed immediately.
		log.Warnf("failure parsing certificate for secret %s, will refresh secret immediately %v",
			scannerSecret.GetName(), err)
		return 0
	}

	return getScannerSecretDurationFromCertificate(scannerCert)
}

func (o *localscannerOperatorImpl) issueScannerCertificates() error {
	ctx, cancel := context.WithTimeout(o.ctx, issueCertificatesTimeout)
	defer cancel()
	requestID := uuid.NewV4().String() // FIXME validate response has the same request ID
	msg := &central.MsgFromSensor{
		Msg: &central.MsgFromSensor_IssueLocalScannerCertsRequest{
			IssueLocalScannerCertsRequest: &central.IssueLocalScannerCertsRequest{
				RequestId: requestID,
			},
		},
	}
	select {
	case o.responsesC <- msg:
		log.Infof("Request to issue local Scanner certificates sent to Central succesfully: %v", msg)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *localscannerOperatorImpl) fetchLocalScannerSecrets() (*v1.Secret, *v1.Secret, error) {
	ctx, cancel := context.WithTimeout(o.ctx, fetchSecretsTimeout)
	defer cancel()

	// FIXME multierror
	localScannerCredsSecret, err := o.secretsClient.Get(ctx, localScannerCredentialsSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "for secret %s", localScannerCredentialsSecretName)
	}
	localScannerDBCredsSecret, err := o.secretsClient.Get(ctx, localScannerDBCredentialsSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "for secret %s", localScannerDBCredentialsSecretName)
	}

	return localScannerCredsSecret, localScannerDBCredsSecret, nil
}

func updateLocalScannerSecret(scannerSecret, scannerDBSecert *v1.Secret, certificates *storage.TypedServiceCertificateSet) error {
	// FIXME: validate all fields present
	for _, cert := range certificates.GetServiceCerts() {
		switch cert.GetServiceType() {
		case storage.ServiceType_SCANNER_SERVICE:
			scannerSecret.Data = map[string][]byte{
				mtls.ServiceCertFileName: cert.GetCert().GetCertPem(),
				mtls.CACertFileName:      certificates.GetCaPem(),
				mtls.ServiceKeyFileName:  cert.GetCert().GetKeyPem(),
			}
		case storage.ServiceType_SCANNER_DB_SERVICE:
			scannerDBSecert.Data = map[string][]byte{
				mtls.ServiceCertFileName: cert.GetCert().GetCertPem(),
				mtls.CACertFileName:      certificates.GetCaPem(),
				mtls.ServiceKeyFileName:  cert.GetCert().GetKeyPem(),
			}

		default:
			return errors.New("FIXME")
		}
	}

	return nil
}

// When any of the secrets is missing this returns and err such that k8sErrors.IsNotFound(err) is true
// On success it returns the duration after which the secrets should be refreshed
func (o *localscannerOperatorImpl) refreshLocalScannerSecrets(issueCertsResponse *central.IssueLocalScannerCertsResponse) (time.Duration, error) {
	localScannerCredsSecret, localScannerDBCredsSecret, err := o.fetchLocalScannerSecrets()
	if err != nil {
		// FIXME wrap
		return 0, err
	}

	if issueCertsResponse.GetError() != nil {
		// FIXME Wrap
		return 0, errors.New(issueCertsResponse.GetError().GetMessage())
	}

	if err := updateLocalScannerSecret(localScannerCredsSecret, localScannerDBCredsSecret, issueCertsResponse.GetCertificates()); err != nil {
		// FIXME wrap
		return 0, err
	}

	ctx, cancel := context.WithTimeout(o.ctx, updateSecretsTimeout)
	defer cancel()
	// FIXME do a loop, and apply pattern elsewhere
	localScannerCredsSecret, err = o.secretsClient.Update(ctx, localScannerCredsSecret, metav1.UpdateOptions{})
	if err != nil {
		// FIXME wrap
		return 0, err
	}
	localScannerDBCredsSecret, err = o.secretsClient.Update(ctx, localScannerDBCredsSecret, metav1.UpdateOptions{})
	if err != nil {
		// FIXME wrap
		return 0, err
	}

	timeToRefresh := getScannerSecretsDuration(localScannerCredsSecret, localScannerDBCredsSecret)
	return timeToRefresh, nil
}
