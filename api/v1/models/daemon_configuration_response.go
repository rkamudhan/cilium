package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// DaemonConfigurationResponse Response to a daemon configuration request. Contains the adddresing
// information and configuration settings.
//
// swagger:model DaemonConfigurationResponse
type DaemonConfigurationResponse struct {

	// Addressing information of node
	Addressing *NodeAddressing `json:"addressing,omitempty"`

	// Configuration settings
	Configuration *Configuration `json:"configuration,omitempty"`
}

// Validate validates this daemon configuration response
func (m *DaemonConfigurationResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddressing(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateConfiguration(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DaemonConfigurationResponse) validateAddressing(formats strfmt.Registry) error {

	if swag.IsZero(m.Addressing) { // not required
		return nil
	}

	if m.Addressing != nil {

		if err := m.Addressing.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("addressing")
			}
			return err
		}
	}

	return nil
}

func (m *DaemonConfigurationResponse) validateConfiguration(formats strfmt.Registry) error {

	if swag.IsZero(m.Configuration) { // not required
		return nil
	}

	if m.Configuration != nil {

		if err := m.Configuration.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("configuration")
			}
			return err
		}
	}

	return nil
}
