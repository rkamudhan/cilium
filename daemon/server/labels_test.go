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
package server

import (
	"errors"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

var (
	lbls = labels.Labels{
		"foo":    labels.NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2":   labels.NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		"key":    labels.NewLabel("key", "", common.CiliumLabelSource),
		"foo==":  labels.NewLabel("foo==", "==", common.CiliumLabelSource),
		`foo\\=`: labels.NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		`//=/`:   labels.NewLabel(`//=/`, "", common.CiliumLabelSource),
		`%`:      labels.NewLabel(`%`, `%ed`, common.CiliumLabelSource),
	}

	wantSecCtxLbls = policy.Identity{
		ID: 123,
		Endpoints: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		Labels: lbls,
	}
)

func (s *DaemonSuite) TestGetLabelsIDOK(c *C) {
	s.d.OnPutLabels = func(lblsReceived labels.Labels, contID string) (*policy.Identity, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return &wantSecCtxLbls, true, nil
	}

	secCtxLabl, _, err := s.c.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLabl, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsIDFail(c *C) {
	s.d.OnPutLabels = func(lblsReceived labels.Labels, contID string) (*policy.Identity, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil, false, errors.New("Reached maximum valid IDs")
	}

	_, _, err := s.c.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Reached maximum valid IDs"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsOK(c *C) {
	s.d.OnGetLabels = func(id policy.NumericIdentity) (*policy.Identity, error) {
		c.Assert(id, Equals, policy.NumericIdentity(123))
		return &wantSecCtxLbls, nil
	}

	lblsReceived, err := s.c.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(*lblsReceived, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsFail(c *C) {
	s.d.OnGetLabels = func(id policy.NumericIdentity) (*policy.Identity, error) {
		c.Assert(id, Equals, policy.NumericIdentity(123))
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabels(123)
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsBySHA256OK(c *C) {
	s.d.OnGetLabelsBySHA256 = func(sha256sum string) (*policy.Identity, error) {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		return &wantSecCtxLbls, nil
	}

	lblsReceived, err := s.c.GetLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
	c.Assert(err, Equals, nil)
	c.Assert(*lblsReceived, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsBySHA256Fail(c *C) {
	s.d.OnGetLabelsBySHA256 = func(sha256sum string) (*policy.Identity, error) {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestDeleteLabelsByUUIDOK(c *C) {
	s.d.OnDeleteLabelsByUUID = func(id policy.NumericIdentity, contID string) error {
		c.Assert(id, Equals, policy.NumericIdentity(123))
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil
	}

	err := s.c.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestDeleteLabelsByUUIDFail(c *C) {
	s.d.OnDeleteLabelsByUUID = func(id policy.NumericIdentity, contID string) error {
		c.Assert(id, Equals, policy.NumericIdentity(123))
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return errors.New("Unable to contact consul")
	}

	err := s.c.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestDeleteLabelsBySHA256OK(c *C) {
	s.d.OnDeleteLabelsBySHA256 = func(sha256sum, contID string) error {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil
	}

	err := s.c.DeleteLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049",
		"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestDeleteLabelsBySHA256Fail(c *C) {
	s.d.OnDeleteLabelsBySHA256 = func(sha256sum, contID string) error {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return errors.New("Unable to contact consul")
	}

	err := s.c.DeleteLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049",
		"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestGetMaxLabelIDOK(c *C) {
	s.d.OnGetMaxLabelID = func() (policy.NumericIdentity, error) {
		return policy.NumericIdentity(100), nil
	}

	maxID, err := s.c.GetMaxLabelID()
	c.Assert(err, Equals, nil)
	c.Assert(maxID, Equals, policy.NumericIdentity(100))
}

func (s *DaemonSuite) TestGetMaxLabelIDFail(c *C) {
	s.d.OnGetMaxLabelID = func() (policy.NumericIdentity, error) {
		return 0, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetMaxLabelID()
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true, Commentf("error %s", err))
}
