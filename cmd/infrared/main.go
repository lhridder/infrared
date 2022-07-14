package main

import (
	"flag"
	"github.com/haveachin/infrared"
	"github.com/haveachin/infrared/api"
	"log"
	"os"
)

const (
	envPrefix     = "INFRARED_"
	envConfigPath = envPrefix + "CONFIG_PATH"
)

const (
	clfConfigPath = "config-path"
)

var (
	configPath = "./configs"
)

func envString(name string, value string) string {
	envString := os.Getenv(name)
	if envString == "" {
		return value
	}

	return envString
}

func initEnv() {
	configPath = envString(envConfigPath, configPath)
}

func initFlags() {
	flag.StringVar(&configPath, clfConfigPath, configPath, "path of all proxy configs")
	flag.Parse()
}

func init() {
	initEnv()
	initFlags()
}

func main() {
	log.Println("Loading global config")
	err := infrared.LoadGlobalConfig()
	if err != nil {
		log.Println(err)
		return
	}

	var cfgs []*infrared.ProxyConfig
	outCfgs := make(chan *infrared.ProxyConfig)

	if infrared.Config.UseRedisConfig {
		log.Println("Loading proxy configs from redis")
		cfgs, err = infrared.LoadProxyConfigsFromRedis()
		if err != nil {
			log.Printf("Failed loading proxy configs from redis; error: %s", err)
			return
		}
		go func() {
			if err := infrared.WatchRedisConfigs(outCfgs); err != nil {
				log.Println("Failed watching redis configs; error:", err)
			}
		}()
	} else {
		log.Printf("Loading proxy configs from %s", configPath)
		cfgs, err = infrared.LoadProxyConfigsFromPath(configPath, false)
		if err != nil {
			log.Printf("Failed loading proxy configs from %s; error: %s", configPath, err)
			return
		}

		go func() {
			if err := infrared.WatchProxyConfigFolder(configPath, outCfgs); err != nil {
				log.Println("Failed watching config folder; error:", err)
				log.Println("SYSTEM FAILURE: CONFIG WATCHER FAILED")
			}
		}()
	}

	var proxies []*infrared.Proxy
	for _, cfg := range cfgs {
		proxies = append(proxies, &infrared.Proxy{
			Config: cfg,
		})
	}

	gateway := infrared.Gateway{ReceiveProxyProtocol: infrared.Config.ReceiveProxyProtocol}
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

	if infrared.Config.ApiEnabled && !infrared.Config.UseRedisConfig {
		go api.ListenAndServe(configPath, infrared.Config.ApiBind)
	}

	if infrared.Config.GeoIPenabled {
		log.Println("Loading GeoIPDB")
		err := gateway.LoadDB()
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Loading Redis")
		err = gateway.ConnectRedis()
		if err != nil {
			log.Println(err)
			return
		}
		if infrared.Config.MojangAPIenabled {
			log.Println("Loading Mojang API instance")
			gateway.LoadMojangAPI()
			err := gateway.GenerateKeys()
			if err != nil {
				return
			}
		}
	}

	if infrared.Config.PrometheusEnabled {
		err := gateway.EnablePrometheus(infrared.Config.PrometheusBind)
		if err != nil {
			log.Println(err)
			return
		}

		if infrared.Config.TrackBandwith {
			go func() {
				for {
					gateway.TrackBandwith()
				}
			}()
		}
	}

	if !infrared.Config.UnderAttack {
		go func() {
			for {
				gateway.ClearCps()
			}
		}()
	}

	log.Println("Starting gateway listeners")
	if err := gateway.ListenAndServe(proxies); err != nil {
		log.Fatal("Gateway exited; error: ", err)
	}

	gateway.KeepProcessActive()
}
