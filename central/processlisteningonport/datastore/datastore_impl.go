package datastore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/stackrox/rox/central/metrics"
	countMetrics "github.com/stackrox/rox/central/metrics"
	processIndicatorStore "github.com/stackrox/rox/central/processindicator/datastore"
	"github.com/stackrox/rox/central/processlisteningonport/store"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/uuid"
)

type datastoreImpl struct {
	storage            store.Store
	indicatorDataStore processIndicatorStore.DataStore
}

var (
	plopSAC = sac.ForResource(resources.DeploymentExtension)
	log     = logging.LoggerForModule()
)

func newDatastoreImpl(
	storage store.Store,
	indicatorDataStore processIndicatorStore.DataStore,
) *datastoreImpl {
	return &datastoreImpl{
		storage:            storage,
		indicatorDataStore: indicatorDataStore,
	}
}

func (ds *datastoreImpl) GetPlopsFromDB(ctx context.Context) []*storage.ProcessListeningOnPortStorage {
        plopsFromDB := []*storage.ProcessListeningOnPortStorage{}
        ds.WalkAll(ctx,
                func(plop *storage.ProcessListeningOnPortStorage) error {
                        plopsFromDB = append(plopsFromDB, plop)
                        return nil
                })


        return plopsFromDB
}

func convertPlopFromStorageToPlopFromSensor(plopStorage *storage.ProcessListeningOnPortStorage) *storage.ProcessListeningOnPortFromSensor {
	log.Infof("In convertPlopFromStorageToPlopFromSensor plopStorage: %+v", plopStorage)
	return &storage.ProcessListeningOnPortFromSensor{
		Port:           plopStorage.Port,
		Protocol:       plopStorage.Protocol,
		Process:        plopStorage.Process,
		CloseTimestamp: plopStorage.CloseTimestamp,
		// Storage does not have ClusterId which PlopFromSensor has, but this does not seem
		// to be a problem. Might want to examine this more.
		// ClusterId:	plopStorage.ClusterId,
	}
}

func (ds *datastoreImpl) getUnmatchedPlopsFromDB(ctx context.Context) ([]*storage.ProcessListeningOnPortStorage, error) {
	plopsFromDB := []*storage.ProcessListeningOnPortStorage{}
	err := ds.WalkAll(ctx,
		func(plop *storage.ProcessListeningOnPortStorage) error {
			if plop.ProcessIndicatorId == "" {
				plopsFromDB = append(plopsFromDB, plop)
			}
			return nil
		})

	return plopsFromDB, err
}

func (ds *datastoreImpl) getUnmatchedPlopsAndConvert(ctx context.Context) ([]*storage.ProcessListeningOnPortFromSensor, error) {

	portProcesses := make([]*storage.ProcessListeningOnPortFromSensor, 0)
	unmatchedIds := make([]string, 0)
	unmatchedPLOPs, _ := ds.getUnmatchedPlopsFromDB(ctx)

	for _, val := range unmatchedPLOPs {
		unmatchedIds = append(unmatchedIds, val.Id)
		plop := convertPlopFromStorageToPlopFromSensor(val)
		portProcesses = append(portProcesses, plop)
	}

	// Unmatched plop objects are deleted and added back in to avoid duplicate rows.
	// Deleting unmatched plops is not the most efficient solution.
	// Instead plopObjects should be set correctly in AddProcessListeningOnPort.
	err := ds.storage.DeleteMany(ctx, unmatchedIds)

	return portProcesses, err
}

type PlopInfo struct {
	normalizedPLOPs		[]*storage.ProcessListeningOnPortFromSensor
	completedInBatch	[]*storage.ProcessListeningOnPortFromSensor
	indicatorsMap		map[string]*storage.ProcessIndicator
	existingPLOPMap		map[string]*storage.ProcessListeningOnPortStorage

}

func (ds *datastoreImpl) getPlopInfo(
	ctx context.Context,
	portProcesses ...*storage.ProcessListeningOnPortFromSensor,
) (*PlopInfo, error) {

	indicatorIds := make([]string, 0)
	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		// PLOP is a Postgres-only feature, do nothing.
		log.Warnf("Tried to add PLOP not on Postgres, ignore: %+v", portProcesses)
		return nil, nil
	}

	if ok, err := plopSAC.WriteAllowed(ctx); err != nil {
		return nil, err
	} else if !ok {
		return nil, sac.ErrResourceAccessDenied
	}

	if portProcesses == nil || len(portProcesses) == 0 {
		return nil, nil
	}

	//plopInfo.normalizedPLOPs, plopInfo.completedInBatch = normalizePLOPs(portProcesses)
	normalizedPLOPs, completedInBatch := normalizePLOPs(portProcesses)

	// TODO ROX-14376: The next two calls, fetchIndicators and fetchExistingPLOPs, have to
	// be done in a single join query fetching both ProcessIndicator and needed
	// bits from PLOP.
	indicatorsMap, indicatorIds, err := ds.fetchIndicators(ctx, normalizedPLOPs...)
	//plopInfo.indicatorsMap, indicatorIds, err = ds.fetchIndicators(ctx, plopInfo.normalizedPLOPs...)
	if err != nil {
		return nil, err
	}

	existingPLOPMap, err := ds.fetchExistingPLOPs(ctx, indicatorIds)
	//plopInfo.existingPLOPMap, err = ds.fetchExistingPLOPs(ctx, indicatorIds)
	if err != nil {
		return nil, err
	}

	plopInfo := &PlopInfo{
		normalizedPLOPs:	normalizedPLOPs,
		completedInBatch:	completedInBatch,
		indicatorsMap:		indicatorsMap,
		existingPLOPMap:	existingPLOPMap,
	}

	return plopInfo, nil
}

func (ds *datastoreImpl) getPlopObjectsToUpsert(
	ctx context.Context,
	plopInfo *PlopInfo,
) ([]*storage.ProcessListeningOnPortStorage, error) {


	plopObjects := []*storage.ProcessListeningOnPortStorage{}
	for _, val := range plopInfo.normalizedPLOPs {
		indicatorID := ""
		var processInfo *storage.ProcessIndicatorUniqueKey

		key := getPlopProcessUniqueKey(val)

		if indicator, ok := plopInfo.indicatorsMap[key]; ok {
			indicatorID = indicator.GetId()
			log.Debugf("Got indicator %s: %+v", indicatorID, indicator)
		} else {
			countMetrics.IncrementOrphanedPLOPCounter(val.GetClusterId())
			log.Warnf("Found no matching indicators for %s", key)
			processInfo = val.Process
		}

		plopKey := getPlopKeyFromParts(val.GetProtocol(), val.GetPort(), indicatorID)

		existingPLOP, prevExists := plopInfo.existingPLOPMap[plopKey]

		// There are three options:
		// * We found an existing PLOP object with different close timestamp.
		//   It has to be updated.
		// * We found an existing PLOP object with the same close timestamp.
		//   Nothing has to be changed (XXX: Ideally it has to be excluded from
		//   the upsert later on).
		// * No existing PLOP object, create a new one with whatever close
		//   timestamp we have received and fetched indicator ID.
		if prevExists && existingPLOP.CloseTimestamp != val.CloseTimestamp {
			log.Debugf("Got existing PLOP: %+v", existingPLOP)

			existingPLOP.CloseTimestamp = val.CloseTimestamp
			existingPLOP.Closed = existingPLOP.CloseTimestamp != nil
			plopObjects = append(plopObjects, existingPLOP)
		}

		if !prevExists {
			if val.CloseTimestamp != nil {
				// We try to close a not existing Endpoint, something is wrong
				log.Warnf("Found no matching PLOP to close for %s", key)
			}

			plopObjects = addNewPLOP(plopObjects, indicatorID, processInfo, val)
		}
	}

	// Verify what to do about pairs of open/close events that close the
	// lifecycle within the batch. There are only few options:
	// * If an existing open PLOP is present in the db, they will do nothing
	// * If an existing closed PLOP is present in the db, they will update the
	// timestamp
	// * If no existing PLOP is present, they will create a new closed PLOP
	for _, val := range plopInfo.completedInBatch {
		indicatorID := ""
		//var processInfo *storage.ProcessIndicatorUniqueKey

		key := getPlopProcessUniqueKey(val)

		if indicator, ok := plopInfo.indicatorsMap[key]; ok {
			indicatorID = indicator.GetId()
			log.Debugf("Got indicator %s: %+v", indicatorID, indicator)
		} else {
			countMetrics.IncrementOrphanedPLOPCounter(val.GetClusterId())
			log.Warnf("Found no matching indicators for %s", key)
			//processInfo = val.Process
		}

		plopKey := getPlopKeyFromParts(val.GetProtocol(), val.GetPort(), indicatorID)

		existingPLOP, prevExists := plopInfo.existingPLOPMap[plopKey]

		if prevExists {
			log.Debugf("Got existing PLOP to update timestamp: %+v", existingPLOP)

			if existingPLOP.CloseTimestamp != nil &&
				existingPLOP.CloseTimestamp != val.CloseTimestamp {

				// An existing closed PLOP, update timestamp
				existingPLOP.CloseTimestamp = val.CloseTimestamp
				plopObjects = append(plopObjects, existingPLOP)
			}

			// Add nothing if the PLOP is active, i.e. CloseTimestamp == nil
		}

		if !prevExists {
			if val.CloseTimestamp == nil {
				// This events should always be closing by definition
				log.Warnf("Found active PLOP completed in the batch %+v", val)
			}

			// Commenting out the next line of code is a hack 
			// to get TestProcessListeningOnPortReprocessCloseBeforeRetrying in reprocessor.go to pass
			// The difficulty is with distinguishing between the following two cases 
			//
			// 1. Adds an open plop with no matching indicator
			// 2. Adds the indicator for the plop 
			// 3. Adds a batch where the plop is closed and then opened
			// 4. Retries the plops that were not matched to processes
			//
			// 1. Adds an open plop with no matching indicator
			// 2. Adds the indicator for the plop 
			// 3. Adds the closed plop
			// 4. Retries the plops that were not matched to processes
			//
			// The solution is that when a plop is opened and closed in the same batch
			// it will not appear in the table at all. That way when the retry is done
			// the state will be that of the unmatched listening endpoint, which is correct.
			// Commented out code left here for now.

			//plopObjects = addNewPLOP(plopObjects, indicatorID, processInfo, val)
		}
	}
	return plopObjects, nil
}

// getPlopObjectsToUpsertForRetry and getPlopObjectsToUpsert will be probably be merged into one function
// That or there will be some other refactoring
func (ds *datastoreImpl) getPlopObjectsToUpsertForRetry(
	ctx context.Context,
	plopInfo *PlopInfo,
) ([]*storage.ProcessListeningOnPortStorage, error) {

	if plopInfo == nil || plopInfo.normalizedPLOPs == nil {
		return nil, nil
	}

	plopObjects := []*storage.ProcessListeningOnPortStorage{}
	log.Infof("plopInfo.normalizedPLOPs= %+v", plopInfo.normalizedPLOPs)
	for _, val := range plopInfo.normalizedPLOPs {
		indicatorID := ""
		var processInfo *storage.ProcessIndicatorUniqueKey

		key := getPlopProcessUniqueKey(val)

		if indicator, ok := plopInfo.indicatorsMap[key]; ok {
			indicatorID = indicator.GetId()
			log.Debugf("Got indicator %s: %+v", indicatorID, indicator)
		} else {
			countMetrics.IncrementOrphanedPLOPCounter(val.GetClusterId())
			log.Warnf("Found no matching indicators for %s", key)
			processInfo = val.Process
		}

		plopKey := getPlopKeyFromParts(val.GetProtocol(), val.GetPort(), indicatorID)

		_, prevExists := plopInfo.existingPLOPMap[plopKey]

		if !prevExists {
			if val.CloseTimestamp != nil {
				// We try to close a not existing Endpoint, something is wrong
				log.Warnf("Found no matching PLOP to close for %s", key)
			}

			plopObjects = addNewPLOP(plopObjects, indicatorID, processInfo, val)
		}
	}

	// completedInBatch should not be needed for retries as that should mean that a 
	// port was opened and closed without being matched to a process indicator first.
	// It means that the port is closed and it should be in whatever state the table
	// already has it being in. Either closed, open, or non-existant.
	// Leaving it here for now until there are unit tests that are impacted by it.

	// Verify what to do about pairs of open/close events that close the
	// lifecycle within the batch. There are only few options:
	// * If an existing open PLOP is present in the db, they will do nothing
	// * If an existing closed PLOP is present in the db, they will update the
	// timestamp
	// * If no existing PLOP is present, they will create a new closed PLOP
	for _, val := range plopInfo.completedInBatch {
		indicatorID := ""
		var processInfo *storage.ProcessIndicatorUniqueKey

		key := getPlopProcessUniqueKey(val)

		if indicator, ok := plopInfo.indicatorsMap[key]; ok {
			indicatorID = indicator.GetId()
			log.Debugf("Got indicator %s: %+v", indicatorID, indicator)
		} else {
			countMetrics.IncrementOrphanedPLOPCounter(val.GetClusterId())
			log.Warnf("Found no matching indicators for %s", key)
			processInfo = val.Process
		}

		plopKey := getPlopKeyFromParts(val.GetProtocol(), val.GetPort(), indicatorID)

		existingPLOP, prevExists := plopInfo.existingPLOPMap[plopKey]

		if prevExists {
			log.Debugf("Got existing PLOP to update timestamp: %+v", existingPLOP)

			if existingPLOP.CloseTimestamp != nil &&
				existingPLOP.CloseTimestamp != val.CloseTimestamp {

				// An existing closed PLOP, update timestamp
				existingPLOP.CloseTimestamp = val.CloseTimestamp
				plopObjects = append(plopObjects, existingPLOP)
			}

			// Add nothing if the PLOP is active, i.e. CloseTimestamp == nil
		}

		if !prevExists {
			if val.CloseTimestamp == nil {
				// This events should always be closing by definition
				log.Warnf("Found active PLOP completed in the batch %+v", val)
			}

			plopObjects = addNewPLOP(plopObjects, indicatorID, processInfo, val)
		}
	}
	return plopObjects, nil
}

func (ds *datastoreImpl) AddProcessListeningOnPort(
	ctx context.Context,
	portProcesses ...*storage.ProcessListeningOnPortFromSensor,
) error {

	defer metrics.SetDatastoreFunctionDuration(
		time.Now(),
		"ProcessListeningOnPort",
		"AddProcessListeningOnPort",
	)

	// Separating out getting the updates needed and doing the updates
	// seemed like a good idea. Sod did refactoring so that
	// there is a separation of functions using postgres and manipulating
	// data from postgres. It enables unit tests without postgres
	// and greater flexibility and reusability.

	plopInfo, err := ds.getPlopInfo(ctx, portProcesses...)
	plopObjects, err := ds.getPlopObjectsToUpsert(ctx, plopInfo)

	if err != nil {
		return err
	}

	// Now save actual PLOP objects
	return ds.storage.UpsertMany(ctx, plopObjects)
}

func (ds *datastoreImpl) RetryAddProcessListeningOnPort(ctx context.Context) error {

	defer metrics.SetDatastoreFunctionDuration(
		time.Now(),
		"ProcessListeningOnPort",
		"RetryAddProcessListeningOnPort",
	)

	portProcesses, _ := ds.getUnmatchedPlopsAndConvert(ctx)
	plopInfo, err := ds.getPlopInfo(ctx, portProcesses...)
	plopObjects, err := ds.getPlopObjectsToUpsertForRetry(ctx, plopInfo)

	if err != nil {
		return err
	}

	// Now save actual PLOP objects
	return ds.storage.UpsertMany(ctx, plopObjects)
}

func (ds *datastoreImpl) GetProcessListeningOnPort(
	ctx context.Context,
	deploymentID string,
) (
	processesListeningOnPorts []*storage.ProcessListeningOnPort, err error,
) {
	if ok, err := plopSAC.ReadAllowed(ctx); err != nil {
		return nil, err
	} else if !ok {
		return nil, sac.ErrResourceAccessDenied
	}

	processesListeningOnPorts, err = ds.storage.GetProcessListeningOnPort(ctx, deploymentID)

	if err != nil {
		log.Warnf("In GetProcessListeningOnPort. Query for deployment %s returned err: %+v", deploymentID, err)
		return nil, err
	}

	if processesListeningOnPorts == nil {
		log.Warnf("In GetProcessListeningOnPort. Query for deployment %s returned nil", deploymentID)
	}

	return processesListeningOnPorts, nil
}

func (ds *datastoreImpl) WalkAll(ctx context.Context, fn WalkFn) error {
	if ok, err := plopSAC.ReadAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	return ds.storage.Walk(ctx, fn)
}

func (ds *datastoreImpl) RemoveProcessListeningOnPort(ctx context.Context, ids []string) error {
	if ok, err := plopSAC.WriteAllowed(ctx); err != nil {
		return err
	} else if !ok {
		return sac.ErrResourceAccessDenied
	}

	return ds.removePLOP(ctx, ids)
}

func (ds *datastoreImpl) removePLOP(ctx context.Context, ids []string) error {

	if len(ids) == 0 {
		return nil
	}

	return ds.storage.DeleteMany(ctx, ids)
}

// fetchExistingPLOPs: Query already existing PLOP objects belonging to the
// specified process indicators.
//
// XXX: This function queries all PLOP, no matter if they are matching port +
// protocol we've got or not. This means potentially dangerous corner cases
// when one process listens to a huge number of ports. To address it we could
// introduce filtering by port and protocol to the query, and even without
// extra indices PostgreSQL will be able to do it relatively efficiently using
// bitmap scan.
func (ds *datastoreImpl) fetchExistingPLOPs(
	ctx context.Context,
	indicatorIds []string,
) (map[string]*storage.ProcessListeningOnPortStorage, error) {

	var existingPLOPMap = map[string]*storage.ProcessListeningOnPortStorage{}

	if len(indicatorIds) == 0 {
		return existingPLOPMap, nil
	}

	// If no corresponding processes found, we can't verify if the PLOP
	// object is opening/closing an existing one. Collect existingPLOPMap
	// only if there are some matching indicators.
	existingPLOPs, err := ds.storage.GetByQuery(ctx, search.NewQueryBuilder().
		AddStrings(search.ProcessID, indicatorIds...).ProtoQuery())
	if err != nil {
		return nil, err
	}

	for _, val := range existingPLOPs {
		key := getPlopKey(val)

		// A bit of paranoia is always good
		if old, ok := existingPLOPMap[key]; ok {
			log.Warnf("A PLOP %s is already present, overwrite with %s",
				old.GetId(), val.GetId())
		}

		existingPLOPMap[key] = val
	}

	return existingPLOPMap, nil
}

// fetchIndicators: Query all needed process indicators references from PLOPS
// in one go. Besides the indicator map it also returns the list of ids for
// convenience to pass it further.
func (ds *datastoreImpl) fetchIndicators(
	ctx context.Context,
	portProcesses ...*storage.ProcessListeningOnPortFromSensor,
) (map[string]*storage.ProcessIndicator, []string, error) {

	var (
		indicatorLookups []*v1.Query
		indicatorIds     []string
		indicatorsMap    = map[string]*storage.ProcessIndicator{}
	)

	for _, val := range portProcesses {
		if val.Process == nil {
			log.Warnf("Got PLOP object without Process information, ignore: %+v", val)
			continue
		}

		indicatorLookups = append(indicatorLookups,
			search.NewQueryBuilder().
				AddExactMatches(search.ContainerName, val.Process.ContainerName).
				AddExactMatches(search.PodID, val.Process.PodId).
				AddExactMatches(search.ProcessName, val.Process.ProcessName).
				AddExactMatches(search.ProcessArguments, val.Process.ProcessArgs).
				AddExactMatches(search.ProcessExecPath, val.Process.ProcessExecFilePath).
				ProtoQuery())
	}

	indicatorsQuery := search.DisjunctionQuery(indicatorLookups...)
	log.Debugf("Sending query: %s", indicatorsQuery.String())
	indicators, err := ds.indicatorDataStore.SearchRawProcessIndicators(ctx, indicatorsQuery)
	if err != nil {
		return nil, nil, err
	}

	for _, val := range indicators {
		key := getProcessUniqueKey(val)

		// A bit of paranoia is always good
		if old, ok := indicatorsMap[key]; ok {
			log.Warnf("An indicator %s is already present, overwrite with %s",
				old.GetId(), val.GetId())
		}

		indicatorsMap[key] = val
		indicatorIds = append(indicatorIds, val.GetId())
	}

	return indicatorsMap, indicatorIds, nil
}

// OpenClosedPLOPs is a convenient type alias to use in PLOP normalization
type OpenClosedPLOPs struct {
	open   []*storage.ProcessListeningOnPortFromSensor
	closed []*storage.ProcessListeningOnPortFromSensor
}

// normalizePLOPs
//
// In the batch of PLOP events there could be many open & close events for the
// same combination of port, protocol, process. Find and squash them into a
// single event.
//
// Open/close state will be calculated from the total number of open/close
// events in the batch, assuming every single open will eventually be followed
// by close. In this way in the case of:
// * Out-of-order events, we would be able to establish correct status
// * Pairs split across two batches, the status will be correct after processing both batches
// * Lost events, the status will be incorrect
//
// A special case is when the batch has equal number of open/close events. For
// such cases the agreement is they do not contribute anything for already
// existing PLOP events, and produce a closed PLOP event if nothing is found in
// the db.
//
// Another alternative would be to set the status based on the final PLOP
// event, which will produce the same results for case 2 and 3. But such
// approach will produce incorrect status in the case 1 as well, so counting
// seems to be more preferrable.
//
// The function returns two slices of PLOP events, the first one contains
// events that have to change existing PLOP status, the second one contains
// those events that have to be verified against existing PLOP events (i.e.
// every open has matching close whithin the batch.
func normalizePLOPs(
	plops []*storage.ProcessListeningOnPortFromSensor,
) (normalizedResult []*storage.ProcessListeningOnPortFromSensor,
	completedEvents []*storage.ProcessListeningOnPortFromSensor,
) {

	normalizedMap := map[string]OpenClosedPLOPs{}
	normalizedResult = []*storage.ProcessListeningOnPortFromSensor{}
	completedEvents = []*storage.ProcessListeningOnPortFromSensor{}

	for _, val := range plops {
		key := getPlopKeyFromParts(
			val.GetProtocol(),
			val.GetPort(),
			getPlopProcessUniqueKey(val),
		)

		if prev, ok := normalizedMap[key]; ok {

			if val.GetCloseTimestamp() == nil {
				prev.open = append(prev.open, val)
			} else {
				prev.closed = append(prev.closed, val)
			}

			normalizedMap[key] = prev

		} else {

			newValue := OpenClosedPLOPs{
				open:   []*storage.ProcessListeningOnPortFromSensor{},
				closed: []*storage.ProcessListeningOnPortFromSensor{},
			}

			if val.GetCloseTimestamp() == nil {
				newValue.open = append(newValue.open, val)
			} else {
				newValue.closed = append(newValue.closed, val)
			}

			normalizedMap[key] = newValue
		}
	}

	for _, value := range normalizedMap {
		sortByCloseTimestamp(value.open)
		sortByCloseTimestamp(value.closed)
		nOpen := len(value.open)
		nClosed := len(value.closed)

		if nOpen == nClosed {
			completedEvents = append(completedEvents, value.closed[nClosed-1])
			continue
		}

		// Take the last open PLOP if there are more open in total, otherwise
		// the last closed PLOP
		if nOpen > nClosed {
			normalizedResult = append(normalizedResult, value.open[nOpen-1])
		} else {
			normalizedResult = append(normalizedResult, value.closed[nClosed-1])
		}
	}

	return normalizedResult, completedEvents
}

func getProcessUniqueKeyFromParts(containerName string,
	podID string,
	processName string,
	processArgs string,
	processExecFilePath string,
) string {
	return fmt.Sprintf("%s_%s_%s_%s_%s",
		containerName,
		podID,
		processName,
		processArgs,
		processExecFilePath,
	)
}

func getPlopProcessUniqueKey(plop *storage.ProcessListeningOnPortFromSensor) string {
	return getProcessUniqueKeyFromParts(
		plop.Process.ContainerName,
		plop.Process.PodId,
		plop.Process.ProcessName,
		plop.Process.ProcessArgs,
		plop.Process.ProcessExecFilePath,
	)
}

func getProcessUniqueKey(process *storage.ProcessIndicator) string {
	return getProcessUniqueKeyFromParts(
		process.GetContainerName(),
		process.GetPodId(),
		process.GetSignal().GetName(),
		process.GetSignal().GetArgs(),
		process.GetSignal().GetExecFilePath(),
	)
}

func getPlopKeyFromParts(protocol storage.L4Protocol, port uint32, indicatorID string) string {
	return fmt.Sprintf("%d_%d_%s",
		protocol,
		port,
		indicatorID,
	)
}

func getPlopKey(plop *storage.ProcessListeningOnPortStorage) string {
	return getPlopKeyFromParts(plop.GetProtocol(), plop.GetPort(), plop.GetProcessIndicatorId())
}

func sortByCloseTimestamp(values []*storage.ProcessListeningOnPortFromSensor) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].GetCloseTimestamp().Compare(values[j].GetCloseTimestamp()) == -1
	})
}

func addNewPLOP(plopObjects []*storage.ProcessListeningOnPortStorage,
	indicatorID string,
	processInfo *storage.ProcessIndicatorUniqueKey,
	value *storage.ProcessListeningOnPortFromSensor) []*storage.ProcessListeningOnPortStorage {

	if value == nil {
		return plopObjects
	}

	newPLOP := &storage.ProcessListeningOnPortStorage{
		// XXX, ResignatingFacepalm: Use regular GENERATE ALWAYS AS
		// IDENTITY, which would require changes in store generator
		Id:                 uuid.NewV4().String(),
		Port:               value.Port,
		Protocol:           value.Protocol,
		ProcessIndicatorId: indicatorID,
		Process:            processInfo,
		Closed:             value.CloseTimestamp != nil,
		CloseTimestamp:     value.CloseTimestamp,
	}

	return append(plopObjects, newPLOP)
}
