package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	csrf "github.com/utrack/gin-csrf"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	ID   uint `gorm:"primarykey"`
	Name string
}

var db *gorm.DB

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
	db.Create(&User{Name: "Alice"})
	db.Create(&User{Name: "Bob"})
}

// SQL Injection-safe query using GORM's prepared statement behavior
func getUserByID(id uint) (User, error) {
	var user User
	result := db.First(&user, id)
	return user, result.Error
}

// XSS-safe display due to Gin's auto-escaping (unless marked HTML safe)
func displayComment(c *gin.Context) {
	comment := c.PostForm("comment")
	c.HTML(http.StatusOK, "comment.html", gin.H{
		"comment": comment,
		"csrf":    csrf.GetToken(c), // CSRF token for reuse
	})
}

// Safe delete handler with CSRF protection
func deleteUser(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	db.Delete(&User{}, id)
	c.JSON(http.StatusOK, gin.H{"status": "User deleted"})
}

func main() {
	initDB()

	r := gin.Default()

	// Register safe HTML function and load templates
	r.SetFuncMap(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	})
	r.LoadHTMLGlob("templates/*")

	// Add session middleware BEFORE CSRF middleware
	store := cookie.NewStore([]byte("secret-session-key"))
	r.Use(sessions.Sessions("mysession", store))

	// Add CSRF middleware
	r.Use(csrf.Middleware(csrf.Options{
		Secret: "a-32-byte-long-secret-key-goes-here!",
		ErrorFunc: func(c *gin.Context) {
			c.String(400, "CSRF token invalid or missing")
			c.Abort()
		},
	}))

	// Routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "comment.html", gin.H{
			"csrf": csrf.GetToken(c),
		})
	})
	r.POST("/comment", displayComment)
	r.POST("/delete/:id", deleteUser)

	fmt.Println("Server running on http://localhost:8080")
	r.Run(":8080")
}
