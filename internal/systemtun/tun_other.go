//go:build !windows

package systemtun

import (
	"context"
	"errors"
	"io"
)

func Start(context.Context, string, int, io.Writer) error {
	return errors.New("TUN mode is supported only in the Windows portable package")
}
