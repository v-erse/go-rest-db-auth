Simple backend REST API with auth written in Go.

![dashboard](screenshot.png)

(It shows password hash and salt only for testing purposes, to make sure everything's working)

Features:

-   SQLite database
-   Secure auth (passwords encrypted and salted)
-   User sessions (in-memory session store)
-   Basic html dashboard

Libraries/packages used:

-   ORM: [GORM](https://github.com/go-gorm/gorm)
-   Web Framework: [Gin](https://github.com/gin-gonic/gin)
-   Session middleware: [Gorilla Sessions](https://github.com/gorilla/sessions)
-   CSS Framework: [Tailwind](https://tailwindcss.com/)
-   JS Framework: [Alpine](https://github.com/alpinejs/alpine)


How to use:
- clone
- `npm install` 
- `npm run build` to generate css with Tailwind and Postcss
- `cd src` and `go run .` to start server