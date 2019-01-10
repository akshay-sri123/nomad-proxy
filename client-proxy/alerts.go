package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/mitchellh/mapstructure"
)

type nomadBody struct {
	Name        string
	Datacenters []string
	TaskGroups  []struct {
		Name  string
		Count int
		Tasks []map[string]interface{} `json:"Tasks"`
	}
}

func generateCabotAlertBody(checkName, cabotQuery string, value int) []byte {
	var data = []byte(fmt.Sprintf(`
	{
		"name": "%s",
		"active": true,
		"importance": "ERROR",
		"frequency": 5,
		"debounce": 0, 
		"calculated_status": "passing",
		"query": "%s",
		"host": "http://adapter.india.infra.trustingsocial.com:9090",
		"check_type": "<",
		"value": "%d",
		"expected_num_hosts": 0,
		"allowed_num_failures": 0
		}`, checkName, cabotQuery, value))

	return data
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func fireCabotAlert(checkName, cabotQuery string, value int) {
	jsonData := generateCabotAlertBody(checkName, cabotQuery, value)
	url := *cabotAddr + "/api/prometheus_checks/?format=api"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+basicAuth("admin", "admin"))
	client := &http.Client{}
	// alertResponse := checkIfAlertExists(checkName)
	// if alertResponse == "[]" {
	// 	fmt.Printf("Creating alert for: %s\n", checkName)
	// 	response, err := client.Do(req)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	defer response.Body.Close()
	// 	fmt.Println("Status:", response.StatusCode)
	// }
	fmt.Printf("Creating alert for: %s\n", checkName)
	response, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	fmt.Println("Status:", response.StatusCode)
}

// func checkIfAlertExists(checkName string) string {
// 	getURL := *cabotAddr + "/api/prometheus_checks/?name=" + checkName
// 	request, err := http.NewRequest("GET", getURL, nil)
// 	if err != nil {
// 		panic(err)
// 	}
// 	request.Header.Set("Content-Type", "application/json")
// 	request.Header.Add("Authorization", "Basic "+basicAuth("admin", "admin"))
// 	client := &http.Client{}

// 	response, err := client.Do(request)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer response.Body.Close()
// 	fmt.Println("Status: ", response.StatusCode)
// 	body, _ := ioutil.ReadAll(response.Body)
// 	return string(body)
// }

func constructCabotQuery(checkName, taskGroupName string) string {
	datacenter := "central_monitoring"
	promQuery := fmt.Sprintf("nomad_job_summary_%s{datacenter=\\\"%s\\\",status=\\\"running\\\",task_group=\\\"%s\\\"}",
		checkName, datacenter, taskGroupName)
	return promQuery
}

func createCabotAlert(body *jobPayload) {
	var nomadBody nomadBody
	mapstructure.Decode(body.Job, &nomadBody)
	taskGroups := nomadBody.TaskGroups[0]
	taskGroupName := taskGroups.Name
	checkName := nomadBody.Name
	checkValue := taskGroups.Count

	fireCabotAlert(checkName, constructCabotQuery(checkName, taskGroupName), checkValue)
}

func createAlerts(body *jobPayload) {
	createCabotAlert(body)
}
