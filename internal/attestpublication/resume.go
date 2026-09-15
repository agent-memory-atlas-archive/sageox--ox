package attestpublication

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

// PublishExport holds publication ownership before reading either the journal or
// export. Once journaled, the archived bytes remain authoritative on every retry.
func (publisher Publisher) PublishExport(ctx context.Context, repoID, exportDir, outputDir string) (PublishResult, error) {
	journalPath := filepath.Join(outputDir, "attest-upload.json")
	return withPublicationLock(ctx, journalPath, func() (PublishResult, error) {
		journal, err := LoadJournal(journalPath)
		var archive Package
		if errors.Is(err, os.ErrNotExist) {
			archive, err = BuildPackage(exportDir, filepath.Join(outputDir, "attest-run.zip"))
		} else if err == nil {
			archive, err = packageFromJournal(journal)
		}
		if err != nil {
			return PublishResult{}, fmt.Errorf("read frozen Attest package: %w", err)
		}
		return publisher.publish(ctx, repoID, journalPath, archive)
	})
}

func withPublicationLock(ctx context.Context, journalPath string, publish func() (PublishResult, error)) (PublishResult, error) {
	if err := ctx.Err(); err != nil {
		return PublishResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		return PublishResult{}, err
	}
	lock := flock.New(journalPath+".lock", flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil {
		return PublishResult{}, fmt.Errorf("lock attest publication: %w", err)
	}
	if !locked {
		return PublishResult{}, errors.New("another publication owns this output; retry after it finishes")
	}
	// Never remove the lock file: replacing its inode would allow two owners.
	// The kernel releases ownership even if the process exits before this defer.
	defer lock.Unlock()
	return publish()
}

func packageFromJournal(journal Journal) (Package, error) {
	archiveSHA, size, err := hashFile(journal.ArchivePath)
	if err != nil {
		return Package{}, err
	}
	if archiveSHA != journal.Binding.ArchiveSHA256 || size != journal.Binding.ArchiveSizeBytes {
		return Package{}, errors.New("journaled archive changed; refusing to rebuild or resume different bytes")
	}
	archive, err := zip.OpenReader(journal.ArchivePath)
	if err != nil {
		return Package{}, err
	}
	defer archive.Close()
	read := func(name string) ([]byte, error) {
		entry, err := archive.Open(name)
		if err != nil {
			return nil, err
		}
		defer entry.Close()
		return io.ReadAll(entry)
	}
	manifest, err := read(manifestName)
	if err != nil {
		return Package{}, err
	}
	if digest(manifest) != journal.Binding.ManifestSHA256 {
		return Package{}, errors.New("journaled archive manifest changed")
	}
	runRaw, err := read(runFilename)
	if err != nil {
		return Package{}, err
	}
	if err := validateJSON(runSchema, runRaw); err != nil {
		return Package{}, err
	}
	if err := validateRunSemantics(runRaw); err != nil {
		return Package{}, err
	}
	var run RunIdentity
	if err := json.Unmarshal(runRaw, &run); err != nil {
		return Package{}, err
	}
	pkg := Package{Run: run, Manifest: manifest, ManifestSHA256: digest(manifest), ArchivePath: journal.ArchivePath, ArchiveSHA256: archiveSHA, ArchiveSizeBytes: size}
	if err := journal.Matches(pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}
