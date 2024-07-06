package routes

import (
	controllers "go-jwt-auth/controllers"
	"go-jwt-auth/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.POST("/users", controllers.GetUsers())
	incomingRoutes.POST("/users/:user_id", controllers.GetUser())
}

// MAChauhan$%$#7392
