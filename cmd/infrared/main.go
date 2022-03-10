package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/haveachin/infrared/internal/app/infrared"
	"github.com/haveachin/infrared/internal/pkg/bedrock"
	"github.com/haveachin/infrared/internal/pkg/java"
	"github.com/haveachin/infrared/internal/plugin/webhook"
	"go.uber.org/zap"
)

const (
	envPrefix      = "INFRARED_"
	envConfigPath  = envPrefix + "CONFIG_PATH"
	envPluginsPath = envPrefix + "PLUGINS_PATH"

	clfConfigPath  = "config-path"
	clfPluginsPath = "plugins-path"
)

var (
	configPath  = "config.yml"
	pluginsPath = "plugins"
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
	pluginsPath = envString(envPluginsPath, pluginsPath)
}

func initFlags() {
	flag.StringVar(&configPath, clfConfigPath, configPath, "path of the config file")
	flag.StringVar(&pluginsPath, clfPluginsPath, pluginsPath, "path to the plugins folder")
	flag.Parse()
}

var logger *zap.Logger

func init() {
	initEnv()
	initFlags()
	initConfig()

	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to init logger; err: %s", err)
	}
}

func main() {
	logger.Info("loading proxy from config",
		zap.String("config", configPath),
	)

	bedrockProxy, err := infrared.NewProxy(&bedrock.ProxyConfig{Viper: v})
	if err != nil {
		logger.Error("failed to load proxy", zap.Error(err))
		return
	}

	javaProxy, err := infrared.NewProxy(&java.ProxyConfig{Viper: v})
	if err != nil {
		logger.Error("failed to load proxy", zap.Error(err))
		return
	}

	pluginManager := infrared.PluginManager{
		Plugins: []infrared.Plugin{
			&webhook.Plugin{
				Viper: v,
			},
		},
		Log: logger,
	}

	if err := pluginManager.EnablePlugins(); err != nil {
		logger.Error("failed to enable plugins", zap.Error(err))
		return
	}

	logger.Info("starting proxy")

	go bedrockProxy.ListenAndServe(logger)
	go javaProxy.ListenAndServe(logger)

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	logger.Info("disabeling plugins")
	pluginManager.DisablePlugins()
}
