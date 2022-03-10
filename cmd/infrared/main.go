package main

import (
	"flag"
	"fmt"
	"github.com/haveachin/infrared"
	"github.com/haveachin/infrared/api"
	"log"
	"os"
	"strconv"
	"syscall"
)

const (
	envPrefix               = "INFRARED_"
	envConfigPath           = envPrefix + "CONFIG_PATH"
	envReceiveProxyProtocol = envPrefix + "RECEIVE_PROXY_PROTOCOL"
)

const (
	clfConfigPath           = "config-path"
	clfReceiveProxyProtocol = "receive-proxy-protocol"
)

var (
	configPath           = "./configs"
	receiveProxyProtocol = false
)

func envBool(name string, value bool) bool {
	envString := os.Getenv(name)
	if envString == "" {
		return value
	}

	envBool, err := strconv.ParseBool(envString)
	if err != nil {
		return value
	}

	return envBool
}

func envString(name string, value string) string {
	envString := os.Getenv(name)
	if envString == "" {
		return value
	}

	return envString
}

func initEnv() {
	configPath = envString(envConfigPath, configPath)
	receiveProxyProtocol = envBool(envReceiveProxyProtocol, receiveProxyProtocol)
}

func initFlags() {
	flag.StringVar(&configPath, clfConfigPath, configPath, "path of all proxy configs")
	flag.BoolVar(&receiveProxyProtocol, clfReceiveProxyProtocol, receiveProxyProtocol, "should accept proxy protocol")
	flag.Parse()
}

func init() {
	initEnv()
	initFlags()
}

func main() {
	var rLimit syscall.Rlimit
	rLimit.Max = 999999
	rLimit.Cur = 999999

	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Setting Rlimit ", err)
	}

	log.Println("Loading global config")
	infrared.LoadGlobalConfig()

	log.Println("Loading proxy configs")

	cfgs, err := infrared.LoadProxyConfigsFromPath(configPath, false)
	if err != nil {
		log.Printf("Failed loading proxy configs from %s; error: %s", configPath, err)
		return
	}

	var proxies []*infrared.Proxy
	for _, cfg := range cfgs {
		proxies = append(proxies, &infrared.Proxy{
			Config: cfg,
		})
	}

	outCfgs := make(chan *infrared.ProxyConfig)
	go func() {
		if err := infrared.WatchProxyConfigFolder(configPath, outCfgs); err != nil {
			log.Println("Failed watching config folder; error:", err)
			log.Println("SYSTEM FAILURE: CONFIG WATCHER FAILED")
		}
	}()

	gateway := infrared.Gateway{ReceiveProxyProtocol: receiveProxyProtocol}
	go func() {
		for {
			cfg, ok := <-outCfgs
			if !ok {
				return
			}

			proxy := &infrared.Proxy{Config: cfg}
			if err := gateway.RegisterProxy(proxy); err != nil {
				log.Println("Failed registering proxy; error:", err)
			}
		}
	}()

	if infrared.ApiEnabled {
		go api.ListenAndServe(configPath, infrared.ApiBind)
	}

	if infrared.GeoIPenabled {
		log.Println("Loading GeoIPDB")
		gateway.LoadDB()
		log.Println("Loading Redis")
		err := gateway.ConnectRedis()
		if err != nil {
			log.Println(err)
			return
		}
		if infrared.MojangAPIenabled {
			log.Println("Loading Mojang API instance")
			gateway.LoadMojangAPI()
			err := gateway.GenerateKeys()
			if err != nil {
				return
			}
		}
	}

	if infrared.PrometheusEnabled {
		err := gateway.EnablePrometheus(infrared.PrometheusBind)
		if err != nil {
			log.Println(err)
			return
		}
	}

	if !infrared.UnderAttack {
		go func() {
			for {
				gateway.ClearCps()
			}
		}()
	}

	log.Println("Starting Infrared")
	if err := gateway.ListenAndServe(proxies); err != nil {
		log.Fatal("Gateway exited; error: ", err)
	}

	gateway.KeepProcessActive()
}
