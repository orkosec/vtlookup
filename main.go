package main

import (
	"flag"
	"log"
	"net/http"
	"vtchecker/api"
)

var filePath string

func init() {
	flag.StringVar(&filePath, "file", "", "File path to read hashes from")
}

func main() {

	flag.Parse()

	if filePath != "" {
		api.LoadHash(filePath)
		return
	}

	// body, err := getObject(hash)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// fmt.Println(malwareCheck(body, response))

	// sb := string(body)
	// fmt.Println(sb)

	http.HandleFunc("/vt", api.GetHash)
	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		log.Println("Error starting server:", err)
	}

}
