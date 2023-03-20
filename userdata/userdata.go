package userdata

import (
	"bytes"
	"fmt"
	"text/template"
)

var WindowsRunScriptTemplate = "try { gc -Raw C:/AzureData/CustomData.bin | sc /run.ps1; /run.ps1 -Token \"{{.CallbackToken}}\" } finally { rm -Force -ErrorAction SilentlyContinue /run.ps1 }"

func GetWindowsRunScriptCommand(callbackToken string) ([]byte, error) {
	t, err := template.New("").Parse(WindowsRunScriptTemplate)
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}

	params := struct {
		CallbackToken string
	}{
		CallbackToken: callbackToken,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("error rendering template: %w", err)
	}

	return buf.Bytes(), nil
}
