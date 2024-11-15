package router

import (
	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validator *validator.Validate
}

type ValidationError struct {
	Error map[string]any `json:"error"`
}

func NewValidator() *Validator {
	return &Validator{
		validator: validator.New(validator.WithRequiredStructEnabled()),
	}
}

func (v *Validator) Validate(i any) error {
	return v.validator.Struct(i)
}
