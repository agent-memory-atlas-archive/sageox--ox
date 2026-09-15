package ledger

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sageox/ox/internal/lfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReadLFSFixture(t *testing.T, handler http.HandlerFunc) *readFixture {
	t.Helper()
	f := newReadFixture(t, handler)
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		http.DefaultTransport = previous
	})
	return f
}

func commitReadLFSPointer(t *testing.T, f *readFixture, path string, content []byte) string {
	t.Helper()
	pointer := lfs.FormatPointer("sha256:"+lfs.ComputeOID(content), int64(len(content)))
	commitReadPointer(t, f, path, pointer)
	return pointer
}

func commitReadPointer(t *testing.T, f *readFixture, path, pointer string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(f.source, path)), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(f.source, path), []byte(pointer), 0600))
	readTestGit(t, f.source, "add", "--", path)
	readTestGit(t, f.source, "commit", "-m", "add LFS content")
	readTestGit(t, f.bare, "fetch", f.source, "+refs/heads/main:refs/heads/main")
}

// Failure prevented: batching mixes up out-of-order grants, repeats a shared
// object in the request, or reacquires grants for already verified warm files.
func TestReadSyncLFSBatchHydratesUniqueAndSharedObjects(t *testing.T) {
	first, second := []byte("shared session content\n"), []byte("different plan content\n")
	firstOID, secondOID := lfs.ComputeOID(first), lfs.ComputeOID(second)
	expected := []lfs.BatchObject{{OID: firstOID, Size: int64(len(first))}, {OID: secondOID, Size: int64(len(second))}}
	contents := map[string][]byte{firstOID: first, secondOID: second}
	var batches, downloads atomic.Int32
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/batch") {
			batches.Add(1)
			assert.Equal(t, http.MethodPost, r.Method)
			var request struct {
				Operation string            `json:"operation"`
				Objects   []lfs.BatchObject `json:"objects"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(t, "download", request.Operation)
			assert.ElementsMatch(t, expected, request.Objects)
			response := lfs.BatchResponse{}
			for i := len(request.Objects) - 1; i >= 0; i-- {
				object := request.Objects[i]
				response.Objects = append(response.Objects, lfs.BatchResponseObject{
					OID: object.OID, Size: object.Size, Actions: &lfs.Actions{Download: &lfs.Action{
						Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + object.OID,
					}},
				})
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		downloads.Add(1)
		assert.Equal(t, http.MethodGet, r.Method)
		content, ok := contents[filepath.Base(r.URL.Path)]
		if !assert.True(t, ok, "only a requested object may be downloaded") {
			http.NotFound(w, r)
			return
		}
		w.Write(content)
	})
	files := map[string][]byte{
		"sessions/a/session.md": first, "sessions/b/session.md": first,
		"data/plans/batched/plan.md": second,
	}
	for path, content := range files {
		commitReadLFSPointer(t, f, path, content)
	}
	result := ReadSync(context.Background(), f.opts)
	require.True(t, result.Ready, "%+v", result)
	require.Equal(t, ReadHydration{State: "complete", Required: len(files), Completed: len(files)}, result.Hydration)
	for path, content := range files {
		actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
		require.NoError(t, err)
		require.Equal(t, content, actual, path)
	}
	require.Equal(t, int32(1), batches.Load(), "all unique objects share one batch grant")
	coldDownloads := downloads.Load()
	require.Positive(t, coldDownloads)
	warm := ReadSync(context.Background(), f.opts)
	require.True(t, warm.Ready, "%+v", warm)
	require.Equal(t, result.Head, warm.Head)
	require.Equal(t, int32(1), batches.Load())
	require.Equal(t, coldDownloads, downloads.Load(), "warm verified files require no object downloads")
}

// Failure prevented: a zero-byte artifact's pointer (size 0) was reported as
// missing_hydration before any request, so one empty session file failed the
// whole ledger read. An empty object needs no grant: its content is implied.
func TestReadSyncLFSEmptyObjectMaterializesWithoutBatch(t *testing.T) {
	content := []byte("session content\n")
	var batches atomic.Int32
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/batch") {
			batches.Add(1)
			var request struct {
				Objects []lfs.BatchObject `json:"objects"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			for _, object := range request.Objects {
				assert.NotZero(t, object.Size, "an empty object must never be requested")
			}
			response := lfs.BatchResponse{}
			for _, object := range request.Objects {
				response.Objects = append(response.Objects, lfs.BatchResponseObject{
					OID: object.OID, Size: object.Size, Actions: &lfs.Actions{Download: &lfs.Action{
						Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + object.OID,
					}},
				})
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		w.Write(content)
	})
	commitReadLFSPointer(t, f, "sessions/a/session.md", content)
	commitReadLFSPointer(t, f, "sessions/a/context-trace.jsonl", []byte{})
	result := ReadSync(context.Background(), f.opts)
	require.True(t, result.Ready, "%+v", result)
	require.Equal(t, "complete", result.Hydration.State)
	empty, err := os.ReadFile(filepath.Join(f.opts.Path, "sessions/a/context-trace.jsonl"))
	require.NoError(t, err)
	require.Empty(t, empty)
	require.Equal(t, int32(1), batches.Load(), "only the non-empty object needs a grant")
	warm := ReadSync(context.Background(), f.opts)
	require.True(t, warm.Ready, "%+v", warm)
	require.Equal(t, int32(1), batches.Load(), "a verified empty file needs nothing on warm sync")
}

// Failure prevented: a size-0 pointer naming any other object is materialized
// as an empty file, silently replacing content the pointer never described.
func TestReadSyncLFSEmptyObjectRequiresEmptyOID(t *testing.T) {
	var batches atomic.Int32
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		batches.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	commitReadPointer(t, f, "sessions/a/context-trace.jsonl", lfs.FormatPointer("sha256:"+lfs.ComputeOID([]byte("not empty")), 0))
	result := ReadSync(context.Background(), f.opts)
	require.False(t, result.Ready)
	require.Equal(t, "missing_hydration", result.ErrorClass)
	require.Equal(t, &ReadFailureDetail{Reason: "empty_object_oid_mismatch", Path: "sessions/a/context-trace.jsonl",
		OID: lfs.ComputeOID([]byte("not empty")), ExpectedOID: lfs.ComputeOID(nil)}, result.ErrorDetail)
	require.Zero(t, batches.Load(), "an unhydratable pointer must not reach the server")
}

func TestMaterializeEmptyReadObjectMissingDir(t *testing.T) {
	require.Error(t, materializeEmptyReadObject(filepath.Join(t.TempDir(), "missing", "context-trace.jsonl")))
}

// Failure prevented: ledgers with over 100 unique pointers exceed the backend's
// batch limit, or a later failed batch discards previously verified hydration.
func TestReadSyncLFSBoundedBatchesPreserveProgress(t *testing.T) {
	for _, tc := range []struct{ name, errorClass string }{
		{name: "complete"},
		{name: "later batch foreign", errorClass: "missing_hydration"},
		{name: "later batch denied", errorClass: "denied"},
		{name: "later batch canceled", errorClass: "interrupted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := make(map[string][]byte)
			paths := make(map[string]string)
			for i := range 101 {
				content := []byte(fmt.Sprintf("batched object %03d\n", i))
				oid := lfs.ComputeOID(content)
				contents[oid] = content
				paths[fmt.Sprintf("sessions/bounded/object-%03d.md", i)] = oid
			}
			firstOID := paths["sessions/bounded/object-000.md"]
			paths["sessions/bounded/shared.md"] = firstOID
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var batches, downloads atomic.Int32
			f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/batch") {
					downloads.Add(1)
					content, ok := contents[filepath.Base(r.URL.Path)]
					if !assert.True(t, ok) {
						http.NotFound(w, r)
						return
					}
					w.Write(content)
					return
				}
				batch := batches.Add(1)
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.LessOrEqual(t, len(body), 64*1024, "backend request-body limit")
				var request struct {
					Objects []lfs.BatchObject `json:"objects"`
				}
				assert.NoError(t, json.Unmarshal(body, &request))
				if len(request.Objects) > 100 {
					http.Error(w, "batch object limit exceeded", http.StatusRequestEntityTooLarge)
					return
				}
				if batch == 1 {
					assert.Len(t, request.Objects, 100)
				} else {
					assert.Len(t, request.Objects, 1)
					assert.Equal(t, int32(101), downloads.Load(), "the prior batch, including shared files, remains hydrated")
				}
				if batch == 2 {
					switch tc.name {
					case "later batch denied":
						w.WriteHeader(http.StatusForbidden)
						return
					case "later batch canceled":
						cancel()
						<-r.Context().Done()
						return
					case "later batch foreign":
						request.Objects = []lfs.BatchObject{{OID: firstOID, Size: int64(len(contents[firstOID]))}}
					}
				}
				response := lfs.BatchResponse{}
				for i := len(request.Objects) - 1; i >= 0; i-- {
					object := request.Objects[i]
					response.Objects = append(response.Objects, lfs.BatchResponseObject{
						OID: object.OID, Size: object.Size, Actions: &lfs.Actions{Download: &lfs.Action{
							Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + object.OID,
						}},
					})
				}
				json.NewEncoder(w).Encode(response)
			})
			require.True(t, ReadSync(ctx, f.opts).Ready)
			require.NoError(t, os.MkdirAll(filepath.Join(f.source, "sessions/bounded"), 0700))
			for path, oid := range paths {
				pointer := lfs.FormatPointer("sha256:"+oid, int64(len(contents[oid])))
				require.NoError(t, os.WriteFile(filepath.Join(f.source, path), []byte(pointer), 0600))
			}
			readTestGit(t, f.source, "add", "--", "sessions/bounded")
			readTestGit(t, f.source, "commit", "-m", "add more than one LFS batch")
			readTestGit(t, f.bare, "fetch", f.source, "+refs/heads/main:refs/heads/main")
			result := ReadSync(ctx, f.opts)
			require.Equal(t, tc.errorClass, result.ErrorClass, "%+v", result)
			require.Equal(t, int32(2), batches.Load())
			if tc.errorClass != "" {
				require.False(t, result.Ready)
				require.Equal(t, int32(101), downloads.Load())
				receipt := loadReadReceipt(f.opts.Path, f.opts.RepoID, f.opts.Endpoint)
				require.NotNil(t, receipt)
				require.False(t, receipt.Ready)
				for path, oid := range paths {
					actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
					require.NoError(t, err)
					if path == "sessions/bounded/object-100.md" {
						require.Equal(t, lfs.FormatPointer("sha256:"+oid, int64(len(contents[oid]))), string(actual))
					} else {
						require.Equal(t, contents[oid], actual, path)
					}
				}
				result = ReadSync(context.Background(), f.opts)
				require.Equal(t, int32(3), batches.Load(), "retry requests only the remaining object")
			}
			require.True(t, result.Ready, "%+v", result)
			require.Equal(t, int32(len(paths)), downloads.Load())
			for path, oid := range paths {
				actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
				require.NoError(t, err)
				require.Equal(t, contents[oid], actual, path)
			}
		})
	}
}

// Failure prevented: an incomplete or mismatched batch partially hydrates files
// before discovering that another object's identity, size, or action is invalid.
func TestReadSyncLFSBatchRejectsInvalidResponsesBeforeMaterialization(t *testing.T) {
	firstPath, secondPath := "sessions/a/session.md", "sessions/b/session.md"
	firstOID, secondOID := lfs.ComputeOID([]byte(firstPath+"\n")), lfs.ComputeOID([]byte(secondPath+"\n"))
	secondSize := int64(len(secondPath + "\n"))
	for _, tc := range []struct {
		name   string
		detail ReadFailureDetail
	}{
		{"missing", ReadFailureDetail{Reason: "batch_response_incomplete"}},
		{"duplicate", ReadFailureDetail{Reason: "batch_object_duplicated", OID: firstOID}},
		{"foreign", ReadFailureDetail{Reason: "batch_object_unrequested", OID: lfs.ComputeOID([]byte("unrequested object"))}},
		// An unrequested OID is arbitrary server text that nothing validates.
		// It is dropped rather than republished; the reason still names the condition.
		{"foreign credential", ReadFailureDetail{Reason: "batch_object_unrequested"}},
		{"wrong size", ReadFailureDetail{Reason: "object_size_mismatch", Path: secondPath, OID: secondOID,
			ExpectedSize: readSize(secondSize), ActualSize: readSize(secondSize + 1)}},
		{"missing action", ReadFailureDetail{Reason: "object_missing_actions", Path: secondPath, OID: secondOID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var batches, downloads atomic.Int32
			f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/batch") {
					downloads.Add(1)
					http.Error(w, "invalid batch must not start a download", http.StatusInternalServerError)
					return
				}
				batches.Add(1)
				var request struct {
					Objects []lfs.BatchObject `json:"objects"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				if !assert.Len(t, request.Objects, 2) {
					http.Error(w, "expected a single combined batch", http.StatusBadRequest)
					return
				}
				objects := make([]lfs.BatchResponseObject, 0, 2)
				for _, object := range request.Objects {
					objects = append(objects, lfs.BatchResponseObject{
						OID: object.OID, Size: object.Size, Actions: &lfs.Actions{Download: &lfs.Action{
							Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + object.OID,
						}},
					})
				}
				switch tc.name {
				case "missing":
					objects = objects[:1]
				case "duplicate":
					objects[1] = objects[0]
				case "foreign":
					objects[1].OID = lfs.ComputeOID([]byte("unrequested object"))
				case "foreign credential":
					objects[1].OID = "https://ox:" + readTestToken + "@ledger.invalid/repo.git?sig=" + readTestToken
				case "wrong size":
					objects[1].Size++
				case "missing action":
					objects[1].Actions = nil
				}
				json.NewEncoder(w).Encode(lfs.BatchResponse{Objects: objects})
			})
			require.True(t, ReadSync(context.Background(), f.opts).Ready)
			pointers := map[string]string{}
			for _, path := range []string{firstPath, secondPath} {
				pointers[path] = commitReadLFSPointer(t, f, path, []byte(path+"\n"))
			}
			result := ReadSync(context.Background(), f.opts)
			require.False(t, result.Ready)
			require.Equal(t, "missing_hydration", result.ErrorClass)
			require.Equal(t, &tc.detail, result.ErrorDetail)
			rendered, err := json.Marshal(result)
			require.NoError(t, err)
			for _, forbidden := range []string{readTestToken, f.opts.ReadURL, "?sig=", "ledger.invalid"} {
				require.NotContains(t, string(rendered), forbidden, "a malformed grant must not republish server bytes")
			}
			require.Nil(t, result.LastSuccessfulSync)
			require.Equal(t, int32(1), batches.Load())
			require.Zero(t, downloads.Load(), "validate the entire grant before materializing any object")
			for path, pointer := range pointers {
				actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
				require.NoError(t, err)
				require.Equal(t, pointer, string(actual), path)
			}
			require.False(t, CheckReadiness(context.Background(), f.opts.Path, f.opts.RepoID, f.opts.Endpoint).Ready)
		})
	}
}

// Failure prevented: a refused object reports only "missing_hydration", so
// establishing WHICH object the server refused needs server request logs
// correlated against object storage by hand (ox #946). The counter-risk is the
// obvious fix leaking the server's reflected response into the result.
func TestReadSyncLFSRefusedObjectNamesItselfWithoutLeakingTheResponse(t *testing.T) {
	const path = "sessions/refused/session.md"
	content := []byte("content the server refuses to grant\n")
	for _, tc := range []struct {
		name, errorClass string
		code             int
	}{
		{"object not found", "missing_hydration", http.StatusNotFound},
		{"object gone", "missing_hydration", http.StatusGone},
		{"object forbidden", "denied", http.StatusForbidden},
		{"object unauthorized", "denied", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refuse atomic.Bool
			f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/batch") {
					_, _ = w.Write(content)
					return
				}
				var request struct {
					Objects []lfs.BatchObject `json:"objects"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				response := lfs.BatchResponse{}
				for _, object := range request.Objects {
					granted := lfs.BatchResponseObject{OID: object.OID, Size: object.Size}
					if refuse.Load() {
						// A hostile or careless server reflects the caller's own
						// credential and a signed URL back in the message it controls.
						granted.Error = &lfs.ObjectError{Code: tc.code,
							Message: "token " + readTestToken + " rejected at https://" + r.Host + r.URL.Path + "?sig=" + readTestToken}
					} else {
						granted.Actions = &lfs.Actions{Download: &lfs.Action{
							Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + object.OID,
						}}
					}
					response.Objects = append(response.Objects, granted)
				}
				assert.NoError(t, json.NewEncoder(w).Encode(response))
			})
			require.True(t, ReadSync(context.Background(), f.opts).Ready)
			refuse.Store(true)
			pointer := commitReadLFSPointer(t, f, path, content)

			result := ReadSync(context.Background(), f.opts)
			require.False(t, result.Ready)
			require.Equal(t, tc.errorClass, result.ErrorClass, "naming the object must not change its category")
			require.Equal(t, &ReadFailureDetail{Reason: "object_refused", Path: path,
				OID: lfs.ComputeOID(content), ServerCode: tc.code}, result.ErrorDetail)

			rendered, err := json.Marshal(result)
			require.NoError(t, err)
			for _, forbidden := range []string{readTestToken, f.opts.ReadURL, "?sig=", "rejected at", http.StatusText(tc.code)} {
				require.NotContains(t, string(rendered), forbidden, "result must carry no credential, URL, or response body")
			}

			actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
			require.NoError(t, err)
			require.Equal(t, pointer, string(actual), "a refused object leaves its stub in place")

			refuse.Store(false)
			recovered := ReadSync(context.Background(), f.opts)
			require.True(t, recovered.Ready, "%+v", recovered)
			require.Nil(t, recovered.ErrorDetail, "a recovered sync carries no stale detail")
		})
	}
}

// Failure prevented: readers see partial hydration, or slow object delivery
// makes a revision appear remotely observed later than its actual Git fetch.
func TestReadSyncLFSHydrationPublishesAfterVerification(t *testing.T) {
	content := []byte("verified plan content delivered in two chunks\n")
	oid := lfs.ComputeOID(content)
	started := make(chan time.Time, 1)
	release := make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	defer unblock()
	var batches, downloads atomic.Int32
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/batch") {
			batches.Add(1)
			var request struct {
				Operation string            `json:"operation"`
				Objects   []lfs.BatchObject `json:"objects"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(t, "download", request.Operation)
			assert.Equal(t, []lfs.BatchObject{{OID: oid, Size: int64(len(content))}}, request.Objects)
			json.NewEncoder(w).Encode(lfs.BatchResponse{Objects: []lfs.BatchResponseObject{{
				OID: oid, Size: int64(len(content)), Actions: &lfs.Actions{Download: &lfs.Action{
					Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + oid,
				}},
			}}})
			return
		}
		downloads.Add(1)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Write(content[:8])
		w.(http.Flusher).Flush()
		started <- time.Now().UTC()
		select {
		case <-release:
			w.Write(content[8:])
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first := ReadSync(ctx, f.opts)
	require.True(t, first.Ready, "%+v", first)
	path := "data/plans/hydrated/plan.md"
	pointer := commitReadLFSPointer(t, f, path, content)
	finished := make(chan ReadSyncResult, 1)
	go func() {
		defer close(finished)
		finished <- ReadSync(ctx, f.opts)
	}()
	defer func() {
		unblock()
		cancel()
		for range finished {
		}
	}()
	var objectStarted time.Time
	select {
	case objectStarted = <-started:
	case result := <-finished:
		t.Fatalf("sync completed before object delivery: %+v", result)
	case <-ctx.Done():
		t.Fatal("sync never requested the LFS object")
	}
	// Inspect the durable flag without taking the materializer's held lock.
	invalid := loadReadReceipt(f.opts.Path, f.opts.RepoID, f.opts.Endpoint)
	require.NotNil(t, invalid)
	require.False(t, invalid.Ready)
	require.Equal(t, first.Head, invalid.Head)
	require.Equal(t, first.LastSuccessfulSync, invalid.LastSuccessfulSync)
	actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
	require.NoError(t, err)
	require.Equal(t, pointer, string(actual), "partial object bytes must stay in staging")
	readerCtx, readerCancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer readerCancel()
	called := false
	err = WithReadCheckout(readerCtx, f.opts.Path, f.opts.RepoID, f.opts.Endpoint, func(ReadSyncResult) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called, "a reader cannot enter while hydration holds the checkout lock")
	unblock()
	result := <-finished
	require.True(t, result.Ready, "%+v", result)
	require.Empty(t, result.ErrorClass)
	require.NotNil(t, result.LastSuccessfulSync)
	require.True(t, result.LastSuccessfulSync.After(*first.LastSuccessfulSync))
	require.True(t, result.LastSuccessfulSync.Before(objectStarted), "freshness retains the preceding Git observation time")
	require.Equal(t, ReadHydration{State: "complete", Required: 1, Completed: 1}, result.Hydration)
	actual, err = os.ReadFile(filepath.Join(f.opts.Path, path))
	require.NoError(t, err)
	require.Equal(t, content, actual)
	require.Equal(t, int32(1), batches.Load())
	require.Equal(t, int32(1), downloads.Load())
	warm := ReadSync(ctx, f.opts)
	require.True(t, warm.Ready, "%+v", warm)
	require.Equal(t, result.Head, warm.Head)
	require.True(t, warm.LastSuccessfulSync.After(*result.LastSuccessfulSync))
	require.Equal(t, int32(1), batches.Load(), "unchanged verified content needs no new LFS grant")
	require.Equal(t, int32(1), downloads.Load(), "unchanged warm fetch must retain hydrated bytes")
}

// Failure prevented: a newly added missing object causes already hydrated
// sessions to be replaced by stubs before the failed refresh can restore them.
func TestReadSyncLFSFailedRefreshPreservesEarlierHydration(t *testing.T) {
	retained := []byte("previously verified session content\n")
	retainedOID := lfs.ComputeOID(retained)
	var oldDownloads, missingBatches atomic.Int32
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/batch") {
			var request struct {
				Objects []lfs.BatchObject `json:"objects"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			if !assert.Len(t, request.Objects, 1) {
				return
			}
			requested := request.Objects[0]
			object := lfs.BatchResponseObject{OID: requested.OID, Size: requested.Size}
			if requested.OID == retainedOID {
				object.Actions = &lfs.Actions{Download: &lfs.Action{Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + retainedOID}}
			} else {
				missingBatches.Add(1)
				object.Error = &lfs.ObjectError{Code: 404, Message: "new object unavailable"}
			}
			json.NewEncoder(w).Encode(lfs.BatchResponse{Objects: []lfs.BatchResponseObject{object}})
			return
		}
		oldDownloads.Add(1)
		w.Write(retained)
	})
	oldPath := "sessions/z-retained/session.md"
	commitReadLFSPointer(t, f, oldPath, retained)
	ctx := context.Background()
	first := ReadSync(ctx, f.opts)
	require.True(t, first.Ready, "%+v", first)
	require.Equal(t, int32(1), oldDownloads.Load())
	actual, err := os.ReadFile(filepath.Join(f.opts.Path, oldPath))
	require.NoError(t, err)
	require.Equal(t, retained, actual)

	// The new failure sorts before the old hydrated object, so there is no
	// successful re-download to conceal premature dehydration of existing data.
	newPath := "sessions/a-missing/session.md"
	pointer := commitReadLFSPointer(t, f, newPath, []byte("missing new session\n"))
	failed := ReadSync(ctx, f.opts)
	require.False(t, failed.Ready)
	require.Equal(t, "missing_hydration", failed.ErrorClass)
	require.NotEqual(t, first.Head, failed.Head)
	require.Equal(t, int32(1), missingBatches.Load())
	require.Equal(t, int32(1), oldDownloads.Load(), "existing verified content must be retained locally")
	actual, err = os.ReadFile(filepath.Join(f.opts.Path, oldPath))
	require.NoError(t, err)
	require.Equal(t, retained, actual, "failed refresh must not discard an earlier successful hydration")
	actual, err = os.ReadFile(filepath.Join(f.opts.Path, newPath))
	require.NoError(t, err)
	require.Equal(t, pointer, string(actual))
	receipt := loadReadReceipt(f.opts.Path, f.opts.RepoID, f.opts.Endpoint)
	require.NotNil(t, receipt)
	require.False(t, receipt.Ready)
}

// Failure prevented: a missing/denied/corrupt object overwrites a pointer,
// destroys existing content, or certifies an incompletely materialized HEAD.
func TestReadSyncLFSFailuresPreserveContentAndRecoverLocally(t *testing.T) {
	for _, tc := range []struct {
		name, errorClass string
		objectStatus     int
		omitAction       bool
	}{
		{name: "missing object", objectStatus: 404, errorClass: "missing_hydration"},
		{name: "missing action", omitAction: true, errorClass: "missing_hydration"},
		{name: "corrupt content", errorClass: "missing_hydration"},
		{name: "denied object", objectStatus: 403, errorClass: "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte("expected session data\n")
			oid := lfs.ComputeOID(content)
			f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/batch") {
					object := lfs.BatchResponseObject{OID: oid, Size: int64(len(content))}
					if tc.objectStatus != 0 {
						object.Error = &lfs.ObjectError{Code: tc.objectStatus, Message: "unavailable"}
					} else if !tc.omitAction {
						object.Actions = &lfs.Actions{Download: &lfs.Action{Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + oid}}
					}
					json.NewEncoder(w).Encode(lfs.BatchResponse{Objects: []lfs.BatchResponseObject{object}})
					return
				}
				w.Write([]byte("unverified bytes"))
			})
			ctx := context.Background()
			first := ReadSync(ctx, f.opts)
			require.True(t, first.Ready, "%+v", first)
			path := "sessions/new/session.md"
			pointer := commitReadLFSPointer(t, f, path, content)
			result := ReadSync(ctx, f.opts)
			require.False(t, result.Ready)
			require.Equal(t, tc.errorClass, result.ErrorClass)
			require.NotEqual(t, first.Head, result.Head)
			require.Nil(t, result.LastSuccessfulSync, "incomplete new HEAD has no verified freshness")
			require.Equal(t, "missing", result.Hydration.State)
			actual, err := os.ReadFile(filepath.Join(f.opts.Path, path))
			require.NoError(t, err)
			require.Equal(t, pointer, string(actual))
			for _, original := range []string{"sessions/old/session.md", "data/plans/plan/plan.md"} {
				actual, err := os.ReadFile(filepath.Join(f.opts.Path, original))
				require.NoError(t, err)
				require.Equal(t, original+"\n", string(actual))
			}
			staging, err := filepath.Glob(filepath.Join(f.opts.Path, "sessions/new/.ox-read-object-*"))
			require.NoError(t, err)
			require.Empty(t, staging)
			receipt := loadReadReceipt(f.opts.Path, f.opts.RepoID, f.opts.Endpoint)
			require.NotNil(t, receipt)
			require.False(t, receipt.Ready)
			require.False(t, CheckReadiness(ctx, f.opts.Path, f.opts.RepoID, f.opts.Endpoint).Ready)
			// Recovered bytes establish local readiness, never a new remote timestamp.
			require.NoError(t, os.WriteFile(filepath.Join(f.opts.Path, path), content, 0600))
			t.Setenv("SAGEOX_TOKEN", "")
			recovered := CheckReadiness(ctx, f.opts.Path, f.opts.RepoID, f.opts.Endpoint)
			require.True(t, recovered.Ready, "%+v", recovered)
			require.Nil(t, recovered.LastSuccessfulSync)
		})
	}
}

// Failure prevented: a cold clone is published despite a failed LFS hash check.
func TestReadSyncLFSColdFailureNeverPublishesCheckout(t *testing.T) {
	content := []byte("expected cold clone content\n")
	oid := lfs.ComputeOID(content)
	f := newReadLFSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/batch") {
			json.NewEncoder(w).Encode(lfs.BatchResponse{Objects: []lfs.BatchResponseObject{{OID: oid, Size: int64(len(content)), Actions: &lfs.Actions{Download: &lfs.Action{
				Href: "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/batch") + "/" + oid,
			}}}}})
			return
		}
		w.Write([]byte("bad object"))
	})
	commitReadLFSPointer(t, f, "sessions/cold/session.md", content)
	result := ReadSync(context.Background(), f.opts)
	require.False(t, result.Ready)
	require.Equal(t, "missing_hydration", result.ErrorClass)
	require.Nil(t, result.LastSuccessfulSync)
	require.NoDirExists(t, f.opts.Path)
	staging, err := filepath.Glob(filepath.Join(filepath.Dir(f.opts.Path), ".ox-read-clone-*"))
	require.NoError(t, err)
	require.Empty(t, staging, "only the unpublished failed clone should be removed")
}
