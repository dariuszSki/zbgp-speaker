# iptables-bgp-scraper
This is an app that scrapes iptables rules from NF-INTERCEPT chain for Ziti Services and updates the gobgp server
to distributes these service prefixes out to neighbors. It utilizes gobgp server library to stand up a bgp speaker and 
configures it using gobgp apis. The open source project can be found at [gobgp github](https://github.com/osrg/gobgp)

**Prerequisites**

The configuration file that needs to be created for the bgp speaker. The minimum file content must be as follows:

```toml
[global.config]
    as = 65000
    router-id = "10.10.10.10"
    local-address-list = ["192.168.100.20"]

[global.apply-policy.config]
    import-policy-list = ["policy1"]
    default-import-policy = "reject-route"
    export-policy-list = ["policy2"]
    default-export-policy = "accept-route"

[[neighbors]]
    [neighbors.config]
        peer-as = 65001
        neighbor-address = "192.168.100.200"
```

More about the configuration options can be found at [bgp configuration example](https://github.com/osrg/gobgp/blob/master/docs/sources/configuration.md). 
Keep in mind that th purpise of thsi apop si to use the server to announce prefixes extracted from Ziti Service and not import any rpefizex from neighbors.
Thus, the example shown above is more than enough to satisfy the given purpose.

**Cli options**
```bash
./iptables_bgp_scraper_linux -h
an app that scrapes iptables rules for Ziti Services under NF-INTERCEPTS Chain, then utilizes gobgp server to advertize scraped prefixes to bgp neighbors.

Usage:
  iptables-bgp-scraper [flags]
  iptables-bgp-scraper [command]

Available Commands:
  client      zbgp client command
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version number of iptables-bgp-scraper

Flags:
  -h, --help               help for iptables-bgp-scraper
  -l, --log-level string   specifying log level (default "Info")

Use "iptables-bgp-scraper [command] --help" for more information about a command.

----------------------------------------------

./iptables_bgp_scraper_linux client server -h
This command runs gobgp in server mode that the client can use a a bgp speaker to neighbors

Usage:
  iptables-bgp-scraper client server [flags]

Flags:
  -a, --api-hosts string     specify the hosts that gobgpd listens on (default ":50051")
  -c, --config-file string   specifying a config file
  -t, --config-type string   specifying config type (toml, yaml, json) (default "toml")
  -r, --graceful-restart     flag restart-state in graceful-restart capability (default true)
  -h, --help                 help for server
  -n, --sdnotify             use sd_notify protocol (default true)

Global Flags:
  -l, --log-level string   specifying log level (default "Info")
```

**Example to run in background**
```bash
sudo nohup ./iptables_bgp_scraper client server -c /etc/gobgpd.conf &
```