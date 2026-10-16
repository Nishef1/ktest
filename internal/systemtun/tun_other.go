//go:build !windows

package systemtun

import (
	"context"
	"errors"
	"io"
)

var errWindowsOnly = errors.New("TUN mode is supported only in the Windows portable package")

func Start(context.Context, string, int, io.Writer) error { return errWindowsOnly }

func StartSystem(context.Context, string, Options, io.Writer) error { return errWindowsOnly }

func IsAdmin() bool { return false }

func PhysicalNetwork(context.Context) (string, []string, error) { return "", nil, errWindowsOnly }

func Elevate([]string) error { return errWindowsOnly }
