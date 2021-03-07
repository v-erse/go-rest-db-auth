package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type routeHandler struct {
	db   *gorm.DB
	sess *sessions.CookieStore
}

func hashAndSaltPassword(newUser *User) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("couldn't create salt")
	}

	hash, err := bcrypt.GenerateFromPassword(append([]byte(newUser.Password), salt...), bcrypt.DefaultCost)
	if err != nil {
		panic("couldn't generate hash from password")
	}

	newUser.Salt = string(salt)
	newUser.Password = string(hash)
}

func comparePasswordHash(hashedPassword string, salt string, password string) error {
	saltedPassword := append([]byte(password), []byte(salt)...)
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), saltedPassword)
}

func (rh *routeHandler) signUp(c *gin.Context) {
	// bind json to user object
	newUser := User{}
	if err := c.ShouldBindJSON(&newUser); err != nil {
		if c.ContentType() != "application/json" {
			// if it isn't json, reject
			c.JSON(http.StatusBadRequest, gin.H{"error": "Content-Type isn't application/json"})
			return
		}
		// should bind with json, otherwise return an error
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check if this email is already registered
	oldUser := User{}
	if result := rh.db.First(&oldUser, &User{Email: newUser.Email}); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user with that email already exists"})
		return
	}

	// ideally just pass in &newUser
	hashAndSaltPassword(&newUser)

	// store object in database, if fail, return 500
	if result := rh.db.Create(&newUser); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Couldn't register user"})
		return
	}

	// return 200 and user id
	c.JSON(http.StatusCreated, gin.H{"status": "Signed up"})
}

func (rh *routeHandler) login(c *gin.Context) {
	session, _ := rh.sess.Get(c.Request, "go-api")

	user := User{}
	if err := c.ShouldBindJSON(&user); err != nil {
		// should bind with json, otherwise return an error
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// get user
	userRecord := User{}
	if err := rh.db.First(&userRecord, User{Email: user.Email}).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if userRecord.Email != user.Email {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect email"})
		return
	}

	if err := comparePasswordHash(userRecord.Password, userRecord.Salt, user.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect password"})
		return
	}

	session.Values["user"] = userRecord.Username
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "couldn't log in :("})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status": "Logged in",
		"user": gin.H{
			"username": userRecord.Username,
		},
	})
}

func (rh *routeHandler) logout(c *gin.Context) {
	session, _ := rh.sess.Get(c.Request, "go-api")

	session.Values["user"] = nil
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "couldn't log out :("})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "Logged out"})
}

func (rh *routeHandler) getUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid id type"})
	}

	user := User{}

	result := rh.db.First(&user, User{Model: gorm.Model{ID: uint(id)}})
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Couldn't find user with id %d", id)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func (rh *routeHandler) deleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid id type"})
	}

	user := User{}

	result := rh.db.Delete(&user, User{Model: gorm.Model{ID: uint(id)}})
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Couldn't delete user with id %d", id)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "user deleted"})
}

func (rh *routeHandler) getCurrentUser(c *gin.Context) *User {
	session, _ := rh.sess.Get(c.Request, "go-api")
	loggedInUser := session.Values["user"]
	if loggedInUser == nil {
		return &User{}
	}

	var currentUser User
	if err := rh.db.First(&currentUser, User{Username: loggedInUser.(string)}).Error; err != nil {
		return &User{}
	}

	return &currentUser
}

func (rh *routeHandler) getAllUsers(c *gin.Context) {
	currentUser := rh.getCurrentUser(c)

	var users []User

	result := rh.db.Find(&users)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Couldn't get users"})
		return
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"users":       users,
		"currentUser": currentUser,
	})
}

func newRouteHandler() *routeHandler {
	// open db
	db, err := gorm.Open(sqlite.Open("../gorm.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	// migrate model User
	db.AutoMigrate(&User{})

	// create routeHandler and set db
	rh := routeHandler{}
	rh.db = db

	// session store
	rh.sess = sessions.NewCookieStore([]byte("secret"))

	// return pointer to routeHandler
	return &rh
}

func main() {
	rh := newRouteHandler()

	r := gin.Default()
	r.Static("/styles/", "../static/styles")
	r.LoadHTMLGlob("../static/*.html")

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/users")
	})
	r.POST("/signup", rh.signUp)
	r.POST("/login", rh.login)
	r.POST("/logout", rh.logout)
	r.GET("/users", rh.getAllUsers)
	r.GET("/users/:id", rh.getUser)
	r.DELETE("/users/:id", rh.deleteUser)

	r.Run()
}
