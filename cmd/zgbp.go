package cmd

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	gobgpApi "github.com/osrg/gobgp/v3/api"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	apb "google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v2"
)

const (
	mangleTable = "mangle"
	srcChain    = "PREROUTING"
	dstChain    = "NF-INTERCEPT"
)

type ContextLogData struct {
	topic string
	value error
}

type OptsGobgpd struct {
	ConfigFile      string
	ConfigType      string
	LogLevel        string
	GrpcHosts       string
	GracefulRestart bool
	UseSdNotify     bool
}

func readIptablesChain(ipt *iptables.IPTables, table, srcChain, dstChain string) []string {
	logger.Debugf("checking iptables '%v' link '%v' --> '%v'", table, srcChain, dstChain)

	ruleList, err := ipt.List(table, dstChain)
	if err != nil {
		logger.WithError(err).Error("failed to unlink chain")
	}
	return ruleList
}

func readZfwMapRules(zfwPath string) []string {
	logger.Debugf("reading data from '%v'", zfwPath)

	cmd := exec.Command(zfwPath, "-L")
	output, err := cmd.Output()
	if err != nil {
		logger.WithError(err).Error("failed to read data from zfw")
	}

	return strings.Split(string(output), "\n")
}

func readYamlRouterConfig(configPath string) interface{} {

	// Create a map to store the parsed config data.
	var routerConfig map[interface{}]interface{}

	// Read the YAML file.
	source, err := os.ReadFile(configPath)
	if err != nil {
		logger.WithError(err).Error("failed to read data from config file")
	}

	// Unmarshal the YAML content
	err = yaml.Unmarshal(source, &routerConfig)
	if err != nil {
		logger.WithError(err).Error("failed to convert byte data into yaml struct")
	}

	// Search for the key "listeners".
	for key, value := range routerConfig {
		if key == "listeners" {
			if m, ok := value.([]interface{}); ok {
				for _, n := range m {
					if s, ok := n.(map[interface{}]interface{}); ok {
						for k, v := range s {
							if k == "binding" && v == "tunnel" {
								if t, ok := s["options"].(map[interface{}]interface{}); ok {
									return t["mode"]
								}
							}
						}
					}
				}
			}
		}
	}
	return ""
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func getAsn(path string) string {
	pathList := strings.Fields(path)
	for _, pathElement := range pathList {
		if strings.Split(pathElement, ":")[0] == "local_identifier" {
			logger.Debugf(strings.Split(pathElement, ":")[1])
		}
		if strings.Split(pathElement, ":")[0] == "asn" || strings.Split(pathElement, ":")[0] == "source_asn" {
			return strings.Split(pathElement, ":")[1]
		}
	}
	return ""
}

func getRoutes(pl chan []string, dbscantime *int) {

	for {
		deadline := time.Now().Add(1000 * time.Millisecond)

		gobgpList := []string{}
		var rules []string
		mode := ""
		// Check if iptables or zfw map is the data source
		proxyMode := readYamlRouterConfig("/opt/netfoundry/ziti/ziti-router/config.yml")
		logger.Debugf("%s", proxyMode)
		if str, ok := proxyMode.(string); ok {
			mode = str
		}

		if mode == "tproxy" {
			// Get the iptables handle and read the rules from the NF-INTERCEPT chain.
			ipt, err := iptables.New()
			if err != nil {
				logger.Warningf("Failed to initialize iptables handle")
				continue
			}
			rules = readIptablesChain(ipt, mangleTable, srcChain, dstChain)
		} else if strings.HasPrefix(mode, "tproxy:") {
			// Read ZFW Map
			rules = readZfwMapRules("/opt/openziti/bin/zfw")
		} else {
			// Return empty list
			pl <- gobgpList
		}

		// Create a map of CIDRs to bools to track whether a CIDR has already been added to the gobgpList.
		keys := make(map[string]bool)

		// Iterate over the rules and add each CIDR to the gobgpList if it hasn't already been added.
		for _, rule := range rules {
			splitString := strings.Fields(rule)
			var cidrString string
			_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")
			for _, value := range splitString {
				_, cidr, err := net.ParseCIDR(value)
				if err != nil || cidr.String() == defaultRoute.String() {
					continue
				}
				cidrString = cidr.String()
			}

			// Only add the CIDR to the gobgpList if it hasn't already been added.
			if _, subValue := keys[cidrString]; !subValue {
				keys[cidrString] = true
				if len(cidrString) != 0 {
					gobgpList = append(gobgpList, cidrString)
				}
			}
			logger.Debugf("%v", gobgpList)
		}

		// Send the gobgpList to the channel.
		pl <- gobgpList

		// Log the routes that will be advertised.
		logger.WithFields(map[string]interface{}{"function": "getRoutes"}).Debugf("routes to advertise %v", gobgpList)
		deadline2 := time.Now().Add(1000 * time.Millisecond)
		logger.WithFields(map[string]interface{}{"function": "getRoutes"}).Debugf("it took  %v to get routes", deadline2.Sub(deadline))
		logger.WithFields(map[string]interface{}{"function": "getRoutes"}).Debugf("sleeping for %d s before looping again", *dbscantime)

		// Sleep for the specified amount of time before looping again.
		time.Sleep(time.Duration(*dbscantime) * time.Second)

	}

}

func getHealthChecks(hc chan int) {
	scriptPath := "/opt/netfoundry/erhchecker.pyz"
	for {
		// Calling Sleep method
		time.Sleep(10 * time.Second)
		logger.Infof("run edge router hc script @'%v'", scriptPath)

		var exitCode int
		var outbuf, errbuf bytes.Buffer

		// Lookup user ids
		username := "ziggy"
		userObj, err := user.Lookup(username)
		if err != nil {
			logger.WithError(err).Error("failed to lookup user or user does not exist")
		}
		uId, _ := strconv.ParseUint(userObj.Uid, 10, 32)
		gId, _ := strconv.ParseUint(userObj.Gid, 10, 32)
		logger.Debugf("user id %v, user group %v", uId, gId)

		// Set up the command user privileges and run it
		cmd := exec.Command("/usr/bin/python3", scriptPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uId), Gid: uint32(gId)}
		cmd.Stdout = &outbuf
		cmd.Stderr = &errbuf
		err = cmd.Run()
		stdout := outbuf.String()
		stderr := errbuf.String()

		// Process errors
		if err != nil {
			// try to get the exit code
			if exitError, ok := err.(*exec.ExitError); ok {
				ws := exitError.Sys().(syscall.WaitStatus)
				exitCode = ws.ExitStatus()
			}
		} else {
			// success, exitCode should be 0 if go is ok
			ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		}

		logger.Infof("command result, stdout: %v, stderr: %v, exitCode: %v", stdout, stderr, exitCode)

		hc <- exitCode
	}
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringP("config-file", "c", "", "specifying a config file")
	serverCmd.Flags().StringP("config-type", "t", "toml", "specifying config type (toml, yaml, json)")
	serverCmd.Flags().StringP("api-hosts", "a", ":50051", "specify the hosts that gobgpd listens on")
	serverCmd.Flags().BoolP("graceful-restart", "r", true, "flag restart-state in graceful-restart capability")
	serverCmd.Flags().BoolP("sdnotify", "n", true, "use sd_notify protocol")
}

var (
	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "zbgp client command",
		Long: `This command runs zbgp in client mode which will look up the iptables chain named NF-INTERCEPTS
and update the gobgp server with the routes generated by the ziti services`,
		PreRun: zlogs,
		Run:    zgbp,
	}
	serverCmd = &cobra.Command{
		Use:    "server",
		Short:  "gobgp server command",
		Long:   `This command runs gobgp in server mode that the client can use a a bgp speaker to neighbors`,
		PreRun: zlogs,
		Run:    zgbp,
	}
)

func zgbp(cmd *cobra.Command, args []string) {

	cflag, _ := cmd.Flags().GetString("config-file")
	tflag, _ := cmd.Flags().GetString("config-type")
	aflag, _ := cmd.Flags().GetString("api-hosts")
	rflag, _ := cmd.Flags().GetBool("graceful-restart")
	nflag, _ := cmd.Flags().GetBool("sdnotify")

	var opts OptsGobgpd
	opts.ConfigFile = cflag
	opts.ConfigType = tflag
	opts.GrpcHosts = aflag
	opts.GracefulRestart = rflag
	opts.UseSdNotify = nflag

	if opts.ConfigFile != "" {
		go func() {
			zgbpd(opts)
		}()
		time.Sleep(15 * time.Second)
	}

	// Connect to the GoBGP server.
	conn, err := grpc.DialContext(context.TODO(), ":50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.WithError(err).Error("fail to connect to gobgp")
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			logger.WithError(err).Error("Check the gobgp api server")
		}
	}(conn)

	// Get the global BGP configuration.
	client := gobgpApi.NewGobgpApiClient(conn)

	// Get the global BGP configuration.
	bgpConfig, err := client.GetBgp(context.Background(), &gobgpApi.GetBgpRequest{})
	if err != nil {
		logger.WithError(err).Error("fail to get gobgp info with error")
		os.Exit(1)
	}
	logger.Data(&ContextLogData{"Config", nil}).Debug(bgpConfig.Global.String())
	asnLocal := getAsn(bgpConfig.Global.String())
	logger.Info(asnLocal)

	// Get the list of prefixes from ziti services.
	dbscantime := 30
	pl := make(chan []string)
	go getRoutes(pl, &dbscantime)

	// Get health checks for edge router.
	hc := make(chan int)
	go getHealthChecks(hc)

	a1, _ := apb.New(&gobgpApi.OriginAttribute{
		Origin: 0,
	})
	a2, _ := apb.New(&gobgpApi.NextHopAttribute{
		NextHop: "0.0.0.0",
	})
	a3, _ := apb.New(&gobgpApi.AsPathAttribute{
		Segments: []*gobgpApi.AsSegment{
			{
				Type:    2,
				Numbers: []uint32{},
			},
		},
	})
	attrs := []*apb.Any{a1, a2, a3}

	// Start the main loop.
	for {
		// Get the list of new prefixes from ziti services
		newPrefixList := <-pl

		// Get health checks for edge router
		healthCheckReturnCode := <-hc
		logger.Debugf("%v", healthCheckReturnCode)
		if healthCheckReturnCode == 1 {
			newPrefixList = []string{}
		}

		var listReader gobgpApi.GobgpApi_ListPathClient
		var listRequest = gobgpApi.ListPathRequest{
			TableType:      gobgpApi.TableType_LOCAL,
			Family:         &gobgpApi.Family{Afi: gobgpApi.Family_AFI_IP, Safi: gobgpApi.Family_SAFI_UNICAST},
			EnableFiltered: true,
		}

		deadline := time.Now().Add(1000 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()

		listReader, err = client.ListPath(ctx, &listRequest)
		if err != nil {
			logger.WithError(err).Error(`could not request the route list client stream `)
		}

		currentPrefixList := []string{}
		for {
			// Read the gobgp global route table and build a list
			path, err := listReader.Recv()

			if err == io.EOF {
				break
			}
			if err != nil {
				logger.WithError(err).Error("errored reading the route table")
			}

			/* Find out if prefix is local or remote */
			var prefixElements string
			prefixElements = path.Destination.String()
			asn := getAsn(prefixElements)
			logger.Debug(prefixElements)
			if asn == asnLocal || asn == "" {
				currentPrefixList = append(currentPrefixList, path.Destination.GetPrefix())
			}
		}

		logger.Debugf("current local route list: %v", currentPrefixList)
		logger.Debugf("proposed local route list: %v", newPrefixList)

		/* Add new prefixes if any */
		for _, prefix := range newPrefixList {
			if contains(currentPrefixList, prefix) == false {
				logger.Debugf("prefix: %v will be added", prefix)
				prefixSplit := strings.Split(prefix, "/")
				prefixlen, _ := strconv.Atoi(prefixSplit[1])
				nlri, _ := apb.New(&gobgpApi.IPAddressPrefix{
					Prefix:    prefixSplit[0],
					PrefixLen: uint32(prefixlen),
				})

				_, err := client.AddPath(context.Background(), &gobgpApi.AddPathRequest{
					Path: &gobgpApi.Path{
						Family: &gobgpApi.Family{Afi: gobgpApi.Family_AFI_IP, Safi: gobgpApi.Family_SAFI_UNICAST},
						Nlri:   nlri,
						Pattrs: attrs,
					},
				})
				if err != nil {
					logger.WithError(err).Error("failed to add route path")
				}
			}
		}

		/* Delete new prefixes if any */
		for _, prefix := range currentPrefixList {
			if contains(newPrefixList, prefix) == false {
				logger.Debugf("prefix: %v will be deleted", prefix)
				prefixSplit := strings.Split(prefix, "/")
				prefixlen, _ := strconv.Atoi(prefixSplit[1])
				nlri, _ := apb.New(&gobgpApi.IPAddressPrefix{
					Prefix:    prefixSplit[0],
					PrefixLen: uint32(prefixlen),
				})
				_, err = client.DeletePath(context.Background(), &gobgpApi.DeletePathRequest{
					Path: &gobgpApi.Path{
						Family: &gobgpApi.Family{Afi: gobgpApi.Family_AFI_IP, Safi: gobgpApi.Family_SAFI_UNICAST},
						Nlri:   nlri,
						Pattrs: attrs,
					},
				})
				if err != nil {
					logger.WithError(err).Error("failed to delete route path")
				}
			}
		}

		deadline2 := time.Now().Add(1000 * time.Millisecond)
		logger.Infof("update global table: duration %v", deadline2.Sub(deadline))
	}

}
