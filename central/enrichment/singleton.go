package enrichment

import (
	"context"
	"time"

	clusterDataStore "github.com/stackrox/rox/central/cluster/datastore"
	"github.com/stackrox/rox/central/cve/fetcher"
	imageCVEDataStore "github.com/stackrox/rox/central/cve/image/datastore"
	nodeCVEDataStore "github.com/stackrox/rox/central/cve/node/datastore"
	delegatedRegistryConfigDS "github.com/stackrox/rox/central/delegatedregistryconfig/datastore"
	"github.com/stackrox/rox/central/delegatedregistryconfig/delegator"
	"github.com/stackrox/rox/central/delegatedregistryconfig/scanwaiter"
	"github.com/stackrox/rox/central/image/datastore"
	"github.com/stackrox/rox/central/imageintegration"
	imageIntegrationDS "github.com/stackrox/rox/central/imageintegration/datastore"
	"github.com/stackrox/rox/central/integrationhealth/reporter"
	namespaceDataStore "github.com/stackrox/rox/central/namespace/datastore"
	"github.com/stackrox/rox/central/role/sachelper"
	"github.com/stackrox/rox/central/sensor/service/connection"
	signatureIntegrationDataStore "github.com/stackrox/rox/central/signatureintegration/datastore"
	"github.com/stackrox/rox/central/vulnerabilityrequest/suppressor"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/expiringcache"
	"github.com/stackrox/rox/pkg/features"
	imageEnricher "github.com/stackrox/rox/pkg/images/enricher"
	"github.com/stackrox/rox/pkg/metrics"
	nodeEnricher "github.com/stackrox/rox/pkg/nodes/enricher"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sync"
)

var (
	once sync.Once

	ie                    imageEnricher.ImageEnricher
	ne                    nodeEnricher.NodeEnricher
	en                    Enricher
	cf                    fetcher.OrchestratorIstioCVEManager
	manager               Manager
	imageIntegrationStore imageIntegrationDS.DataStore
	metadataCacheOnce     sync.Once
	metadataCache         expiringcache.Cache

	imageCacheExpiryDuration = 4 * time.Hour
)

func initialize() {
	scanDelegator := delegator.New(
		delegatedRegistryConfigDS.Singleton(),
		connection.ManagerSingleton(),
		scanwaiter.Singleton(),
		sachelper.NewClusterNamespaceSacHelper(clusterDataStore.Singleton(), namespaceDataStore.Singleton()),
	)

	ie = imageEnricher.New(imageCVEDataStore.Singleton(), suppressor.Singleton(), imageintegration.Set(),
		metrics.CentralSubsystem, ImageMetadataCacheSingleton(), datastore.Singleton().GetImage, reporter.Singleton(),
		signatureIntegrationDataStore.Singleton().GetAllSignatureIntegrations, scanDelegator)
	ne = nodeEnricher.New(nodeCVEDataStore.Singleton(), metrics.CentralSubsystem)
	en = New(datastore.Singleton(), ie)
	cf = fetcher.SingletonManager()
	initializeManager()
}

func initializeManager() {
	ctx := sac.WithAllAccess(context.Background())
	manager = newManager(imageintegration.Set(), ne, cf)

	imageIntegrationStore = imageIntegrationDS.Singleton()
	integrations, err := imageIntegrationStore.GetImageIntegrations(ctx, &v1.GetImageIntegrationsRequest{})
	if err != nil {
		log.Errorf("unable to use previous integrations: %s", err)
		return
	}
	for _, ii := range integrations {
		// Only upsert autogenerated integrations with a source if the feature is enabled.
		if !features.SourcedAutogeneratedIntegrations.Enabled() && ii.GetAutogenerated() && ii.GetSource() != nil {
			continue
		}
		if err := manager.Upsert(ii); err != nil {
			log.Errorf("unable to use previous integration %s: %v", ii.GetName(), err)
		}
	}
}

// Singleton provides the singleton Enricher to use.
func Singleton() Enricher {
	once.Do(initialize)
	return en
}

// ImageEnricherSingleton provides the singleton ImageEnricher to use.
func ImageEnricherSingleton() imageEnricher.ImageEnricher {
	once.Do(initialize)
	return ie
}

// ImageMetadataCacheSingleton returns the cache for image metadata
func ImageMetadataCacheSingleton() expiringcache.Cache {
	metadataCacheOnce.Do(func() {
		metadataCache = expiringcache.NewExpiringCache(imageCacheExpiryDuration, expiringcache.UpdateExpirationOnGets)
	})
	return metadataCache
}

// NodeEnricherSingleton provides the singleton NodeEnricher to use.
func NodeEnricherSingleton() nodeEnricher.NodeEnricher {
	once.Do(initialize)
	return ne
}

// ManagerSingleton returns the multiplexing manager
func ManagerSingleton() Manager {
	once.Do(initialize)
	return manager
}
