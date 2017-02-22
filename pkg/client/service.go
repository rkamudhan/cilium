//
// Copyright 2016-2017 Authors of Cilium
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
package client

import (
	"github.com/cilium/cilium/api/v1/client/service"
	"github.com/cilium/cilium/api/v1/models"
)

func (c *Client) GetServices() ([]*models.Service, error) {
	if resp, err := c.Service.GetService(nil); err != nil {
		return nil, err
	} else {
		return resp.Payload, nil
	}
}

func (c *Client) GetServiceID(id int64) (*models.Service, error) {
	params := service.NewGetServiceIDParams().WithID(id)
	if resp, err := c.Service.GetServiceID(params); err != nil {
		return nil, err
	} else {
		return resp.Payload, nil
	}
}

func (c *Client) PutServiceID(id int64, svc *models.Service) error {
	params := service.NewPutServiceIDParams().WithID(id).WithConfig(svc)
	_, _, err := c.Service.PutServiceID(params)
	return err
}

func (c *Client) DeleteServiceID(id int64) error {
	params := service.NewDeleteServiceIDParams().WithID(id)
	_, err := c.Service.DeleteServiceID(params)
	return err
}
