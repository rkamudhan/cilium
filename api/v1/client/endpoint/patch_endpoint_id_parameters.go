package endpoint

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
)

// NewPatchEndpointIDParams creates a new PatchEndpointIDParams object
// with the default values initialized.
func NewPatchEndpointIDParams() *PatchEndpointIDParams {
	var ()
	return &PatchEndpointIDParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchEndpointIDParamsWithTimeout creates a new PatchEndpointIDParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchEndpointIDParamsWithTimeout(timeout time.Duration) *PatchEndpointIDParams {
	var ()
	return &PatchEndpointIDParams{

		timeout: timeout,
	}
}

// NewPatchEndpointIDParamsWithContext creates a new PatchEndpointIDParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchEndpointIDParamsWithContext(ctx context.Context) *PatchEndpointIDParams {
	var ()
	return &PatchEndpointIDParams{

		Context: ctx,
	}
}

// NewPatchEndpointIDParamsWithHTTPClient creates a new PatchEndpointIDParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchEndpointIDParamsWithHTTPClient(client *http.Client) *PatchEndpointIDParams {
	var ()
	return &PatchEndpointIDParams{
		HTTPClient: client,
	}
}

/*PatchEndpointIDParams contains all the parameters to send to the API endpoint
for the patch endpoint ID operation typically these are written to a http.Request
*/
type PatchEndpointIDParams struct {

	/*Endpoint
	  TBD


	*/
	Endpoint *models.EndpointChangeRequest
	/*ID
	  String describing an endpoint with the format `[prefix:]id`. If no prefix
	is specified, a prefix of `cilium-local:` is assumed. Not all endpoints
	will be addressable by all endpoint ID prefixes with the exception of the
	local Cilium UUID which is assigned to all endpoints.

	Supported endpoint id prefixes:
	  - cilium-local: Local Cilium endpoint UUID, e.g. cilium-local:3389595
	  - cilium-global: Global Cilium endpoint UUID, e.g. cilium-global:cluster1:nodeX:452343
	  - container-id: Container runtime ID, e.g. container-id:22222
	  - docker-net-endpoint: Docker libnetwork endpoint ID, e.g. docker-net-endpoint:4444


	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch endpoint ID params
func (o *PatchEndpointIDParams) WithTimeout(timeout time.Duration) *PatchEndpointIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch endpoint ID params
func (o *PatchEndpointIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch endpoint ID params
func (o *PatchEndpointIDParams) WithContext(ctx context.Context) *PatchEndpointIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch endpoint ID params
func (o *PatchEndpointIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch endpoint ID params
func (o *PatchEndpointIDParams) WithHTTPClient(client *http.Client) *PatchEndpointIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch endpoint ID params
func (o *PatchEndpointIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEndpoint adds the endpoint to the patch endpoint ID params
func (o *PatchEndpointIDParams) WithEndpoint(endpoint *models.EndpointChangeRequest) *PatchEndpointIDParams {
	o.SetEndpoint(endpoint)
	return o
}

// SetEndpoint adds the endpoint to the patch endpoint ID params
func (o *PatchEndpointIDParams) SetEndpoint(endpoint *models.EndpointChangeRequest) {
	o.Endpoint = endpoint
}

// WithID adds the id to the patch endpoint ID params
func (o *PatchEndpointIDParams) WithID(id string) *PatchEndpointIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the patch endpoint ID params
func (o *PatchEndpointIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PatchEndpointIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	r.SetTimeout(o.timeout)
	var res []error

	if o.Endpoint == nil {
		o.Endpoint = new(models.EndpointChangeRequest)
	}

	if err := r.SetBodyParam(o.Endpoint); err != nil {
		return err
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}