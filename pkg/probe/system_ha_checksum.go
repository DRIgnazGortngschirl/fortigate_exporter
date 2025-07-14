// Copyright 2025 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probe

import (
	"log"

	"github.com/prometheus-community/fortigate_exporter/pkg/http"
	"github.com/prometheus/client_golang/prometheus"
)

type HAChecksum struct {
	Global string            `json:"global"`
	Root   string            `json:"root"`
	All    string            `json:"all"`
	Vdoms  map[string]string `json:"vdoms"`
}

type HAChecksumResults struct {
	IsManageMaster int       `json:"is_manage_master"`
	IsRootMaster   int       `json:"is_root_master"`
	SerialNo       string    `json:"serial_no"`
	Checksum       HAChecksum `json:"checksum"`
}

type HAChecksumResponse struct {
	Results []HAChecksumResults `json:"results"`
}

func probeSystemHAChecksum(c http.FortiHTTP, meta *TargetMetadata) ([]prometheus.Metric, bool) {
	var (
		IsMaster = prometheus.NewDesc(
			"fortigate_ha_member_has_role",
			"Master/Slave information",
			[]string{"role", "serial"}, nil,
		)
		ChecksumSync = prometheus.NewDesc(
			"fortigate_ha_checksum_sync",
			"HA checksum synchronization status (1=synced, 0=out of sync)",
			[]string{"checksum_type", "serial"}, nil,
		)
	)

	var res HAChecksumResponse
	if err := c.Get("api/v2/monitor/system/ha-checksums", "scope=global", &res); err != nil {
		log.Printf("Error: %v", err)
		return nil, false
	}

	m := []prometheus.Metric{}
	
	// Track master/slave roles
	for _, response := range res.Results {
		m = append(m, prometheus.MustNewConstMetric(IsMaster, prometheus.GaugeValue, float64(response.IsManageMaster), "manage_master", response.SerialNo))
		m = append(m, prometheus.MustNewConstMetric(IsMaster, prometheus.GaugeValue, float64(response.IsRootMaster), "root_master", response.SerialNo))
	}

	// Compare checksums between nodes
	if len(res.Results) > 1 {
		// Use first node as reference
		referenceNode := res.Results[0]
		
		for _, node := range res.Results {
			// Check global checksum sync
			globalSync := 1.0
			if node.Checksum.Global != referenceNode.Checksum.Global {
				globalSync = 0.0
			}
			m = append(m, prometheus.MustNewConstMetric(ChecksumSync, prometheus.GaugeValue, globalSync, "global", node.SerialNo))
			
			// Check root checksum sync  
			rootSync := 1.0
			if node.Checksum.Root != referenceNode.Checksum.Root {
				rootSync = 0.0
			}
			m = append(m, prometheus.MustNewConstMetric(ChecksumSync, prometheus.GaugeValue, rootSync, "root", node.SerialNo))
			
			// Check all checksum sync
			allSync := 1.0
			if node.Checksum.All != referenceNode.Checksum.All {
				allSync = 0.0
			}
			m = append(m, prometheus.MustNewConstMetric(ChecksumSync, prometheus.GaugeValue, allSync, "all", node.SerialNo))
			
			// Check vdom checksums
			for vdom, checksum := range node.Checksum.Vdoms {
				vdomSync := 1.0
				if referenceChecksum, exists := referenceNode.Checksum.Vdoms[vdom]; !exists || checksum != referenceChecksum {
					vdomSync = 0.0
				}
				m = append(m, prometheus.MustNewConstMetric(ChecksumSync, prometheus.GaugeValue, vdomSync, "vdom_"+vdom, node.SerialNo))
			}
		}
	}

	return m, true
}
