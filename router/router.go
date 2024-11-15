package router

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func New() *echo.Echo {
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.BodyLimit("2M"))
	e.Use(middleware.Logger())
	e.Use(middleware.CORS()) // TODO: Configure CORS for production
	e.Validator = NewValidator()

	return e
}
