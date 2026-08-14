package dmarcxml

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"
)

// maxUncompressed caps what one attachment may expand to. A DMARC report from a
// large receiver is a few hundred kilobytes; 64 MiB is far past any legitimate
// one and well short of what a hostile zip could otherwise do to a long-running
// process. The mailbox this program reads is, by design, an address that
// anyone on the internet can send to.
const maxUncompressed = 64 << 20

// Unpack decodes one report attachment, whatever it is wrapped in, and returns
// every aggregate report inside it.
//
// Reporters use three containers: raw XML, gzip, and zip — the last of which
// may in principle hold several reports, though in practice holds one. The
// filename is a hint only; content sniffing decides, because filenames arrive
// mangled (".xml.gz" served as ".gz", ".zip" as ".xml"), and a wrong guess here
// would silently drop a report.
func Unpack(filename string, data []byte) ([]Feedback, error) {
	switch {
	case isZip(data):
		return unpackZip(data)

	case isGzip(data):
		fb, err := unpackGzip(data)
		if err != nil {
			return nil, err
		}

		return []Feedback{fb}, nil

	default:
		fb, err := Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("attachment %q: %w", path.Base(filename), err)
		}

		return []Feedback{fb}, nil
	}
}

// IsReportAttachment reports whether a MIME part looks like it carries an
// aggregate report, judged by filename and content type. It is a filter, not a
// decision: Unpack is what actually determines whether the bytes parse.
func IsReportAttachment(filename, contentType string) bool {
	name := strings.ToLower(filename)
	ct := strings.ToLower(contentType)

	switch {
	case strings.HasSuffix(name, ".xml"),
		strings.HasSuffix(name, ".xml.gz"),
		strings.HasSuffix(name, ".gz"),
		strings.HasSuffix(name, ".zip"):
		return true
	}

	switch ct {
	case "application/zip", "application/x-zip-compressed",
		"application/gzip", "application/x-gzip",
		"text/xml", "application/xml":
		return true
	}

	return false
}

func isZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		(data[2] == 3 || data[2] == 5 || data[2] == 7)
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func unpackGzip(data []byte) (Feedback, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Feedback{}, fmt.Errorf("opening gzip attachment: %w", err)
	}
	defer zr.Close()

	xmlData, err := readCapped(zr)
	if err != nil {
		return Feedback{}, fmt.Errorf("reading gzip attachment: %w", err)
	}

	return Parse(bytes.NewReader(xmlData))
}

func unpackZip(data []byte) ([]Feedback, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip attachment: %w", err)
	}

	var reports []Feedback
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}

		fb, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}

		reports = append(reports, fb)
	}

	if len(reports) == 0 {
		return nil, fmt.Errorf("zip attachment contains no .xml entry")
	}

	return reports, nil
}

func readZipEntry(f *zip.File) (Feedback, error) {
	rc, err := f.Open()
	if err != nil {
		return Feedback{}, fmt.Errorf("opening zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	xmlData, err := readCapped(rc)
	if err != nil {
		return Feedback{}, fmt.Errorf("reading zip entry %q: %w", f.Name, err)
	}

	fb, err := Parse(bytes.NewReader(xmlData))
	if err != nil {
		return Feedback{}, fmt.Errorf("zip entry %q: %w", f.Name, err)
	}

	return fb, nil
}

// readCapped reads at most maxUncompressed bytes and reports an error if there
// were more, rather than truncating — half a report parsed is worse than none.
func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxUncompressed+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUncompressed {
		return nil, fmt.Errorf("expands to more than %d bytes", maxUncompressed)
	}

	return data, nil
}
