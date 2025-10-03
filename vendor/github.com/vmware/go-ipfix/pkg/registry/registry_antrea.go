// Copyright 2021 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"github.com/vmware/go-ipfix/pkg/entities"
)

// AUTO GENERATED, DO NOT CHANGE

func loadAntreaRegistry() {
	registerInfoElement(*entities.NewInfoElement("sourcePodNamespace", 100, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourcePodName", 101, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodNamespace", 102, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodName", 103, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourceNodeName", 104, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationNodeName", 105, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationClusterIPv4", 106, 18, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationClusterIPv6", 107, 19, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationServicePort", 108, 2, 56506, 2), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationServicePortName", 109, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyName", 110, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyNamespace", 111, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyName", 112, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyNamespace", 113, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyUID", 114, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyType", 115, 1, 56506, 1), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyUID", 117, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyType", 118, 1, 56506, 1), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyRulePriority", 119, 7, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("packetTotalCountFromSourceNode", 120, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetTotalCountFromSourceNode", 121, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetDeltaCountFromSourceNode", 122, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetDeltaCountFromSourceNode", 123, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketTotalCountFromSourceNode", 124, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetTotalCountFromSourceNode", 125, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketDeltaCountFromSourceNode", 126, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetDeltaCountFromSourceNode", 127, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetTotalCountFromDestinationNode", 128, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetTotalCountFromDestinationNode", 129, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetDeltaCountFromDestinationNode", 130, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetDeltaCountFromDestinationNode", 131, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketTotalCountFromDestinationNode", 132, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetTotalCountFromDestinationNode", 133, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketDeltaCountFromDestinationNode", 134, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetDeltaCountFromDestinationNode", 135, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("tcpState", 136, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("flowType", 137, 1, 56506, 1), 56506)
	registerInfoElement(*entities.NewInfoElement("tcpStatePrevList", 138, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyRuleAction", 139, 1, 56506, 1), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyRuleAction", 140, 1, 56506, 1), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyRuleName", 141, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyRuleName", 142, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourcePodLabels", 143, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodLabels", 144, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("throughput", 145, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseThroughput", 146, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("throughputFromSourceNode", 147, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("throughputFromDestinationNode", 148, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseThroughputFromSourceNode", 149, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseThroughputFromDestinationNode", 150, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("flowEndSecondsFromSourceNode", 151, 14, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("flowEndSecondsFromDestinationNode", 152, 14, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("egressName", 153, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressIP", 154, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("appProtocolName", 155, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("httpVals", 156, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNodeName", 157, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("clusterId", 158, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourcePodUUID", 159, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodUUID", 160, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("sourceNodeUUID", 161, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationNodeUUID", 162, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationServiceUUID", 163, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyUUID", 164, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyUUID", 165, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("egressUUID", 166, 0, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNodeUUID", 167, 0, 56506, 16), 56506)
}
