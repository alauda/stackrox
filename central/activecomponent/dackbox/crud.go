package dackbox

import (
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/dackbox/crud"
	"github.com/stackrox/rox/pkg/dbhelper"
	"github.com/stackrox/rox/pkg/transitional/protocompat/proto"
)

var (
	// Bucket stores the active component.
	Bucket = []byte("active_components")

	// BucketHandler is the bucket's handler.
	BucketHandler = &dbhelper.BucketHandler{BucketPrefix: Bucket}

	// Reader reads storage.ActiveComponent(s) directly from the store.
	Reader = crud.NewReader(
		crud.WithAllocFunction(alloc),
	)

	// Upserter writes storage.ActiveComponent(s) directly to the store.
	Upserter = crud.NewUpserter(
		crud.WithKeyFunction(KeyFunc),
		crud.AddToIndex(),
	)

	// Deleter deletes the storage.ActiveComponent(s) from the store.
	Deleter = crud.NewDeleter(
		crud.RemoveFromIndex(),
	)
)

func init() {
	globaldb.RegisterBucket(Bucket, "Active Component")
}

// KeyFunc returns the key with prefix.
func KeyFunc(msg proto.Message) []byte {
	unPrefixed := []byte(msg.(*storage.ActiveComponent).GetId())
	return dbhelper.GetBucketKey(Bucket, unPrefixed)
}

func alloc() proto.Message {
	return &storage.ActiveComponent{}
}
