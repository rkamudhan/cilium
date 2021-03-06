//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package labels

import (
	"github.com/cilium/cilium/common"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LabelsPrefCfgSuite struct{}

var _ = Suite(&LabelsPrefCfgSuite{})

func (s *LabelsPrefCfgSuite) TestFilterLabels(c *C) {
	wanted := Labels{
		"io.cilium.lizards":     NewLabel("io.cilium.lizards", "web", common.CiliumLabelSource),
		"io.cilium.lizards.k8s": NewLabel("io.cilium.lizards.k8s", "web", common.K8sLabelSource),
	}

	dlpcfg := DefaultLabelPrefixCfg()
	allNormalLabels := map[string]string{
		"io.kubernetes.container.hash":                   "cf58006d",
		"io.kubernetes.container.name":                   "POD",
		"io.kubernetes.container.restartCount":           "0",
		"io.kubernetes.container.terminationMessagePath": "",
		"io.kubernetes.pod.name":                         "my-nginx-3800858182-07i3n",
		"io.kubernetes.pod.namespace":                    "default",
		"io.kubernetes.pod.terminationGracePeriod":       "30",
		"io.kubernetes.pod.uid":                          "c2e22414-dfc3-11e5-9792-080027755f5a",
	}
	allLabels := Map2Labels(allNormalLabels, common.CiliumLabelSource)
	filtered := dlpcfg.FilterLabels(allLabels)
	c.Assert(len(filtered), Equals, 0)
	allLabels["io.cilium.lizards"] = NewLabel("io.cilium.lizards", "web", common.CiliumLabelSource)
	allLabels["io.cilium.lizards.k8s"] = NewLabel("io.cilium.lizards.k8s", "web", common.K8sLabelSource)
	filtered = dlpcfg.FilterLabels(allLabels)
	c.Assert(len(filtered), Equals, 2)
	c.Assert(filtered, DeepEquals, wanted)

	// Making sure we are deep copying the labels
	allLabels["io.cilium.lizards"].Source = "I can change this and doesn't affect any one"
	c.Assert(filtered, DeepEquals, wanted)
}
