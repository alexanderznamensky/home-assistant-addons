package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AlexxIT/SmartScaleConnect/internal"
	"gopkg.in/yaml.v3"
)

const Version = "0.4.4"

const usage = `Usage of scaleconnect:

  -c, --config       Path to config file
  -i, --interactive  Keep STDIN open
  -r, --repeat       Run config every N time (format: 2h45m)
`

func main() {
	var (
		config      string
		repeat      string
		interactive bool
	)

	flag.Usage = func() { fmt.Print(usage) }
	flag.StringVar(&config, "config", "", "")
	flag.StringVar(&config, "c", "", "")
	flag.StringVar(&repeat, "repeat", "", "")
	flag.StringVar(&repeat, "r", "", "")
	flag.BoolVar(&interactive, "interactive", false, "")
	flag.BoolVar(&interactive, "i", false, "")
	flag.Parse()

	log.Printf("scaleconnect version %s\n", Version)

	data, err := readConfig(config)

	// run config once
	if repeat == "" && !interactive {
		if err != nil {
			log.Fatal(err)
		}

		if err = process(data); err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}

	configs := make(chan []byte, 10)

	if data != nil {
		configs <- data

		if repeat != "" {
			var sleep time.Duration
			if sleep, err = time.ParseDuration(repeat); err != nil {
				log.Fatal(err)
			}

			log.Printf("repeat interval: %s\n", sleep)

			go func() {
				for range time.NewTicker(sleep).C {
					configs <- data
				}
			}()
		}
	}

	if interactive {
		go func() {
			// read stdin and process it forever
			reader := bufio.NewReader(os.Stdin)
			for {
				data, err := reader.ReadBytes('\n')
				if err != nil {
					break
				}
				configs <- data
			}
		}()
	}

	go func() {
		for data = range configs {
			if err = process(data); err != nil {
				log.Fatal(err)
			}
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	fmt.Printf("exit with signal: %s\n", <-sigs)
}

const configName = "scaleconnect.yaml"

func readConfig(name string) ([]byte, error) {
	if name != "" {
		// 1. Check if JSON passed as config
		if name[0] == '{' {
			log.Printf("config: using inline JSON config\n")
			return []byte(name), nil
		}

		log.Printf("config: reading %s\n", name)
		return os.ReadFile(name)
	}

	// 3. Check config file in CWD
	if data, err := os.ReadFile(configName); err == nil {
		log.Printf("config: reading %s from current directory\n", configName)
		return data, nil
	}

	// 4. Check config near binary
	ex, err := os.Executable()
	if err != nil {
		return nil, err
	}
	path := filepath.Dir(ex)

	log.Printf("config: reading %s\n", filepath.Join(path, configName))
	data, err := os.ReadFile(filepath.Join(path, configName))
	if err != nil {
		return nil, err
	}

	// change CWD so json file will be near app
	return data, os.Chdir(path)
}

func process(data []byte) error {
	startedAt := time.Now()

	var syncs map[string]struct {
		From any               `yaml:"from"`
		To   string            `yaml:"to"`
		Expr map[string]string `yaml:"expr"`
	}
	if err := yaml.Unmarshal(data, &syncs); err != nil {
		return err
	}

	log.Printf("config: loaded %d sync task(s)\n", len(syncs))

	if len(syncs) == 0 {
		log.Printf("config: no sync tasks found\n")
		return nil
	}

	for name, v := range syncs {
		if v.From == "" || v.To == "" {
			log.Printf("%s: skipped because from/to is empty\n", name)
			continue
		}

		log.Printf("%s: start load data\n", name)
		weights, err := internal.GetWeights(v.From)
		if err != nil {
			log.Printf("%s: load data error: %v\n", name, err)
			continue
		}
		log.Printf("%s: loaded %d weight record(s)\n", name, len(weights))

		if v.Expr != nil {
			log.Printf("%s: start calc expr\n", name)
			if err = internal.Expr(v.Expr, weights); err != nil {
				log.Printf("%s: calc expr error: %v\n", name, err)
				continue
			}
		}

		log.Printf("%s: start write data\n", name)
		if err = internal.SetWeights(v.To, weights); err != nil {
			log.Printf("%s: write data error: %v\n", name, err)
			continue
		}

		log.Printf("%s: OK\n", name)
	}

	log.Printf("process finished in %s\n", time.Since(startedAt).Round(time.Second))
	return nil
}
