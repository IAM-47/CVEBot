package bot

import (
	"errors"
	"fmt"
	"net/url"
)

func cleanURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}
