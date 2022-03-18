package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/haveachin/infrared"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

// ListenAndServe Start Webserver
func ListenAndServe(configPath string, apiBind string) {
	log.Println("Starting WebAPI on " + apiBind)
	router := mux.NewRouter()

	router.HandleFunc("/", getHome()).Methods("GET")
	router.HandleFunc("/proxies", getProxies(configPath)).Methods("GET")
	router.HandleFunc("/proxies/{fileName}", getProxy(configPath)).Methods("GET")
	router.HandleFunc("/proxies/{fileName}", addProxyWithName(configPath)).Methods("POST")
	router.HandleFunc("/proxies/{fileName}", removeProxy(configPath)).Methods("DELETE")

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
			configs = append(configs, file.Name())
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
		fileName := mux.Vars(r)["fileName"]

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
		fileName := mux.Vars(r)["fileName"]

		rawData, err := ioutil.ReadAll(r.Body)
		if err != nil || string(rawData) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		jsonIsValid := checkJSONAndRegister(rawData, fileName, configPath)
		if jsonIsValid {
			w.WriteHeader(http.StatusOK)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{'error': 'domainNames and proxyTo could not be found'}"))
			return
		}
	}
}

// removeProxy respond to delete proxy request
func removeProxy(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		file := mux.Vars(r)["fileName"]

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

	err = os.WriteFile(path, rawData, 0644)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
