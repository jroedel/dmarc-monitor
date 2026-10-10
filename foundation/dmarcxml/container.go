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

// Document is one aggregate report's XML exactly as the reporter wrote it,
// taken out of whatever container it arrived in. Name is the zip entry's name,
// or the attachment's own filename for raw XML and gzip; it is the reporter's
// choice and must not be trusted as a path.
type Document struct {
	Name string
	XML  []byte
}

// Extract takes one report attachment out of its container without parsing it.
//
// Reporters use three containers: raw XML, gzip, and zip — the last of which
// may in principle hold several reports, though in practice holds one. The
// filename is a hint only; content sniffing decides, because filenames arrive
// mangled (".xml.gz" served as ".gz", ".zip" as ".xml"), and a wrong guess here
// would silently drop a report.
func Extract(filename string, data []byte) ([]Document, error) {
	name := path.Base(filename)

	switch {
	case isZip(data):
		return extractZip(data)

	case isGzip(data):
		xmlData, err := gunzip(data)
		if err != nil {
			return nil, err
		}

		return []Document{{Name: strings.TrimSuffix(name, ".gz"), XML: xmlData}}, nil

	default:
		return []Document{{Name: name, XML: data}}, nil
	}
}

// Unpack decodes one report attachment, whatever it is wrapped in, and returns
// every aggregate report inside it.
func Unpack(filename string, data []byte) ([]Feedback, error) {
	docs, err := Extract(filename, data)
	if err != nil {
		return nil, err
	}

	reports := make([]Feedback, 0, len(docs))
	for _, doc := range docs {
		fb, err := Parse(bytes.NewReader(doc.XML))
		if err != nil {
			return nil, fmt.Errorf("attachment %q: %w", doc.Name, err)
		}

		reports = append(reports, fb)
	}

	return reports, nil
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

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("opening gzip attachment: %w", err)
	}
	defer zr.Close()

	xmlData, err := readCapped(zr)
	if err != nil {
		return nil, fmt.Errorf("reading gzip attachment: %w", err)
	}

	return xmlData, nil
}

func extractZip(data []byte) ([]Document, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip attachment: %w", err)
	}

	var docs []Document
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}

		xmlData, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}

		docs = append(docs, Document{Name: path.Base(f.Name), XML: xmlData})
	}

	if len(docs) == 0 {
		return nil, fmt.Errorf("zip attachment contains no .xml entry")
	}

	return docs, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	xmlData, err := readCapped(rc)
	if err != nil {
		return nil, fmt.Errorf("reading zip entry %q: %w", f.Name, err)
	}

	return xmlData, nil
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
