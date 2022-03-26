package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/haveachin/infrared"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// ListenAndServe Start Webserver
func ListenAndServe(configPath string, apiBind string) {
	log.Println("Starting WebAPI on " + apiBind)
	router := mux.NewRouter()

	router.HandleFunc("/", getHome()).Methods("GET")
	router.HandleFunc("/proxies", getProxies(configPath)).Methods("GET")
	router.HandleFunc("/proxies/{name}", getProxy(configPath)).Methods("GET")
	router.HandleFunc("/proxies/{name}", addProxyWithName(configPath)).Methods("POST")
	router.HandleFunc("/proxies/{name}", removeProxy(configPath)).Methods("DELETE")

	err := http.ListenAndServe(apiBind, router)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// getHome
func getHome() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

// getProxies
func getProxies(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var configs []string

		files, err := ioutil.ReadDir(configPath)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		for _, file := range files {
			configs = append(configs, strings.Split(file.Name(), ".json")[0])
		}

		err = json.NewEncoder(w).Encode(&configs)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

// getProxy
func getProxy(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileName := mux.Vars(r)["name"] + ".json"

		jsonFile, err := os.Open(configPath + "/" + fileName)
		defer jsonFile.Close()
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		config, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, err = w.Write(config)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

// addProxyWithName respond to post proxy request
func addProxyWithName(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileName := mux.Vars(r)["name"] + ".json"

		rawData, err := ioutil.ReadAll(r.Body)
		if err != nil || string(rawData) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		jsonIsValid := checkJSONAndRegister(rawData, fileName, configPath)
		if jsonIsValid {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{'success': true, 'message': 'the proxy has been added succesfully'}"))
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{'success': false, 'message': 'domainNames and proxyTo could not be found'}"))
			return
		}
	}
}

// removeProxy respond to delete proxy request
func removeProxy(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		file := mux.Vars(r)["name"] + ".json"

		err := os.Remove(configPath + "/" + file)
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			w.Write([]byte(err.Error()))
			return
		}
	}
}

// checkJSONAndRegister validate proxy configuration
func checkJSONAndRegister(rawData []byte, filename string, configPath string) (successful bool) {
	var cfg infrared.ProxyConfig
	err := json.Unmarshal(rawData, &cfg)
	if err != nil {
		log.Println(err)
		return false
	}

	if len(cfg.DomainNames) < 1 || cfg.ProxyTo == "" {
		return false
	}

	path := configPath + "/" + filename
	temppath := path + ".temp"

	err = os.WriteFile(temppath, rawData, 0644)
	if err != nil {
		log.Println(err)
		return false
	}

	err = os.Rename(temppath, path)
	if err != nil {
		return false
	}

	return true
}
