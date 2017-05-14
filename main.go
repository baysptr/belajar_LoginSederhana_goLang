package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "golang.org/x/crypto/bcrypt"

import "net/http"

var db *sql.DB
var err error

func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "index.html")
}

func login(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "login.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	err := db.QueryRow("select username, password from users where username = ?", username).Scan(&databaseUsername, &databasePassword)

	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))

	if err != nil {
		http.Redirect(res, req, "/login", 301)
	}

	res.Write([]byte("Hello " + databaseUsername))
}

func signup(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "signup.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var user string

	err := db.QueryRow("select username, password from users where username = ?", username).Scan(&user)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error, unable to create your account", 500)
			return
		}

		_, err = db.Exec("insert into users (username, password) values (?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(res, "Server error, unable to create your account", 500)
			return
		}

		res.Write([]byte("User created !"))
		return

	case err != nil:
		http.Error(res, "Server error, unable to create your account", 500)
		return

	default:
		http.Redirect(res, req, "/", 301)
	}
}

func main() {
	db, err = sql.Open("mysql", "root:bayu2505@/belajar_go")
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/", homePage)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.ListenAndServe(":9000", nil)
}
