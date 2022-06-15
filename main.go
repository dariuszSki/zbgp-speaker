package main

import "github.com/dariuszSki/iptables-bgp-scraper/cmd"

func main() {
	err := cmd.Execute()
	if err != nil {
		return
	}
}
