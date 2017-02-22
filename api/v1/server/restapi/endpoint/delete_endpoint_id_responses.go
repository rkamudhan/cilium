package endpoint

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
)

// HTTP code for type DeleteEndpointIDOK
const DeleteEndpointIDOKCode int = 200

/*DeleteEndpointIDOK Success

swagger:response deleteEndpointIdOK
*/
type DeleteEndpointIDOK struct {
}

// NewDeleteEndpointIDOK creates DeleteEndpointIDOK with default headers values
func NewDeleteEndpointIDOK() *DeleteEndpointIDOK {
	return &DeleteEndpointIDOK{}
}

// WriteResponse to the client
func (o *DeleteEndpointIDOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
}

// HTTP code for type DeleteEndpointIDErrors
const DeleteEndpointIDErrorsCode int = 206

/*DeleteEndpointIDErrors Deleted with a number of errors encountered

swagger:response deleteEndpointIdErrors
*/
type DeleteEndpointIDErrors struct {

	/*
	  In: Body
	*/
	Payload int64 `json:"body,omitempty"`
}

// NewDeleteEndpointIDErrors creates DeleteEndpointIDErrors with default headers values
func NewDeleteEndpointIDErrors() *DeleteEndpointIDErrors {
	return &DeleteEndpointIDErrors{}
}

// WithPayload adds the payload to the delete endpoint Id errors response
func (o *DeleteEndpointIDErrors) WithPayload(payload int64) *DeleteEndpointIDErrors {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete endpoint Id errors response
func (o *DeleteEndpointIDErrors) SetPayload(payload int64) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteEndpointIDErrors) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(206)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}

// HTTP code for type DeleteEndpointIDInvalid
const DeleteEndpointIDInvalidCode int = 400

/*DeleteEndpointIDInvalid Invalid endpoint ID format for specified type. Details in error
message


swagger:response deleteEndpointIdInvalid
*/
type DeleteEndpointIDInvalid struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewDeleteEndpointIDInvalid creates DeleteEndpointIDInvalid with default headers values
func NewDeleteEndpointIDInvalid() *DeleteEndpointIDInvalid {
	return &DeleteEndpointIDInvalid{}
}

// WithPayload adds the payload to the delete endpoint Id invalid response
func (o *DeleteEndpointIDInvalid) WithPayload(payload models.Error) *DeleteEndpointIDInvalid {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete endpoint Id invalid response
func (o *DeleteEndpointIDInvalid) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteEndpointIDInvalid) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}

// HTTP code for type DeleteEndpointIDNotFound
const DeleteEndpointIDNotFoundCode int = 404

/*DeleteEndpointIDNotFound Endpoint not found

swagger:response deleteEndpointIdNotFound
*/
type DeleteEndpointIDNotFound struct {
}

// NewDeleteEndpointIDNotFound creates DeleteEndpointIDNotFound with default headers values
func NewDeleteEndpointIDNotFound() *DeleteEndpointIDNotFound {
	return &DeleteEndpointIDNotFound{}
}

// WriteResponse to the client
func (o *DeleteEndpointIDNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
}
