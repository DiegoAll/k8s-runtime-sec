package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Report struct {
	Command string `json:"command"`
	Output  string `json:"output"`
}

func SendReportToServer(command, output string) error {
	report := Report{
		Command: command,
		Output:  output,
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("error al convertir a JSON: %v", err)
	}

	resp, err := http.Post("http://34.27.180.215:8080/report", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error al enviar la solicitud HTTP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("el servidor respondió con un código de estado: %d", resp.StatusCode)
	}

	return nil
}
