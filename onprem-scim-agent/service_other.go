//go:build !windows

package main

import "errors"

func isWindowsServiceProcess() bool {
	return false
}

func runningAsLocalSystem() bool {
	return false
}

func runAsWindowsService(serviceName string, onStart func(), onStop func()) error {
	return errors.New("Windows Service mode is only supported on Windows")
}

func installWindowsService(serviceName, displayName, description, exePath, configPath, logPath string, allowInsecure bool, readableFiles ...string) error {
	return errors.New("Windows Service installation is only supported on Windows")
}

// configPermissionProblems checks Windows DACLs; elsewhere it has nothing to check.
func configPermissionProblems(serviceName, configPath string) []string {
	return nil
}

func uninstallWindowsService(serviceName string) error {
	return errors.New("Windows Service uninstallation is only supported on Windows")
}

func startWindowsService(serviceName string) error {
	return errors.New("Windows Service control is only supported on Windows")
}

func stopWindowsService(serviceName string) error {
	return errors.New("Windows Service control is only supported on Windows")
}
