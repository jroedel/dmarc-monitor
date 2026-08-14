package imapstore

import (
	"fmt"
	"io"
	"mime"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"github.com/jroedel/dmarc-monitor/foundation/dmarcxml"
)

// maxAttachment caps a single decoded part. Aggregate reports are small; a part
// larger than this is not one, and reading it would only be a way for a stranger
// to spend the process's memory. The mailbox is a published address.
const maxAttachment = 32 << 20

// attachment is one candidate report part, still in whatever container the
// reporter chose.
type attachment struct {
	filename    string
	contentType string
	data        []byte
}

func init() {
	// Reports occasionally declare a legacy charset in a part header. The
	// payload is XML and effectively always ASCII, but go-message refuses a
	// charset it does not know, and refusing would lose the report. This
	// registers the common ones.
	message.CharsetReader = charset.Reader
}

// reportAttachments walks a raw RFC 5322 message and returns the parts that
// look like they carry an aggregate report.
//
// Errors on individual parts are collected rather than returned: a message with
// one unreadable part and one good report is a message we want the report from.
// Only a message that cannot be parsed as MIME at all fails outright.
func reportAttachments(r io.Reader) ([]attachment, []error, error) {
	entity, err := message.Read(r)
	if entity == nil {
		return nil, nil, fmt.Errorf("reading message: %w", err)
	}

	var (
		found    []attachment
		problems []error
	)

	walkErr := entity.Walk(func(path []int, part *message.Entity, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, fmt.Errorf("part %v: %w", path, walkErr))

			return nil
		}

		if part.MultipartReader() != nil {
			return nil
		}

		contentType, filename := describe(part)
		if !dmarcxml.IsReportAttachment(filename, contentType) {
			return nil
		}

		data, err := io.ReadAll(io.LimitReader(part.Body, maxAttachment+1))
		switch {
		case err != nil:
			problems = append(problems, fmt.Errorf("reading part %v (%s): %w", path, filename, err))

			return nil
		case len(data) > maxAttachment:
			problems = append(problems, fmt.Errorf("part %v (%s) exceeds %d bytes", path, filename, maxAttachment))

			return nil
		}

		found = append(found, attachment{filename: filename, contentType: contentType, data: data})

		return nil
	})
	if walkErr != nil {
		problems = append(problems, fmt.Errorf("walking message parts: %w", walkErr))
	}

	return found, problems, nil
}

// describe extracts a part's media type and filename.
//
// The filename may be in either Content-Disposition or Content-Type, RFC 2231
// continuations and RFC 2047 encoded-words included; reporters use all of them,
// and the filename is half of how a report attachment is recognised.
func describe(part *message.Entity) (contentType, filename string) {
	contentType, ctParams, err := part.Header.ContentType()
	if err != nil {
		contentType = ""
	}

	_, dispParams, err := part.Header.ContentDisposition()
	if err == nil {
		filename = dispParams["filename"]
	}

	if filename == "" {
		filename = ctParams["name"]
	}

	if decoded, err := new(mime.WordDecoder).DecodeHeader(filename); err == nil {
		filename = decoded
	}

	return strings.ToLower(strings.TrimSpace(contentType)), strings.TrimSpace(filename)
}
