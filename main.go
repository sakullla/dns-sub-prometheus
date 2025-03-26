package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/sakullla/dns-sub-prometheus/share"
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	routingService "github.com/xtls/xray-core/app/router/command"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProxyJSON defines the JSON structure as per the given format
type EcsTag struct {
	Name string `json:"name"`
	Ip   string `json:"ip"`
}

// ProxyJSON defines the JSON structure as per the given format
type ProxyJSON struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

const aliDoHURL = "https://dns.alidns.com/dns-query"
const aliUdpURL = "223.5.5.5:53"
const tencentURL = "119.29.29.29:53"

var dnsServer string
var configGrpc bool
var RuleCache *cache.Cache
var outboundHashCache *cache.Cache
var outboundNameCache *cache.Cache
var ignoreKeyword = []string{"剩余流量", "下次重置", "套餐到期", "Traffic Reset", "Expire Date", "GB | "} // 定义字符串切片

type DNSQuery struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type DoHResponse struct {
	Status   int         `json:"Status"`
	TC       bool        `json:"TC"`
	RD       bool        `json:"RD"`
	RA       bool        `json:"RA"`
	AD       bool        `json:"AD"`
	CD       bool        `json:"CD"`
	Question []DNSQuery  `json:"Question"`
	Answer   []DNSAnswer `json:"Answer"`
}

func init() {
	// 绑定命令行参数到全局变量
	flag.StringVar(&dnsServer, "dns-server", aliUdpURL, "custom dns server")
	flag.BoolVar(&configGrpc, "configGrpc", false, "custom dns server")
	RuleCache = cache.New(10*time.Minute, 10*time.Minute)
	outboundHashCache = cache.New(24*time.Hour, 12*time.Hour)
	outboundNameCache = cache.New(24*time.Hour, 12*time.Hour)
}

// 最小前缀长度
const minPrefixLen = 5

// 获取唯一的最短前缀（不少于 minPrefixLen）
func getUniquePrefix(hash string, history map[string]cache.Item) string {
	for l := minPrefixLen; l <= len(hash); l++ {
		prefix := hash[:l]
		conflict := false
		for _, hr := range history {
			h := hr.Object.(string)
			if len(h) >= l && h[:l] == prefix {
				conflict = true
				break
			}
		}
		if !conflict {
			return prefix
		}
	}
	// 如果都冲突了，返回完整的 hash
	return hash
}

// 获取结构体的 SHA256 哈希值
func getStructHash[T any](data *T) (string, error) {
	marshal, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(marshal)
	return hex.EncodeToString(hash[:]), nil
}

func formatName(proxy *share.ClashProxy, group *string) {
	name := strings.TrimSpace(proxy.Name)
	if *group != "" {
		name = strings.Join([]string{*group, name}, "-")
	}
	proxy.Name = name
}

func main() {
	// 解析命令行参数
	flag.Parse()
	http.HandleFunc("/subscribe", handleRequest)
	http.HandleFunc("/dns", dnsRequest)
	http.HandleFunc("/monitor", monitorRequest)
	fmt.Println("Server is listening on port 36639...")
	log.Fatal(http.ListenAndServe("0.0.0.0:36639", nil))
}

func monitorRequest(w http.ResponseWriter, r *http.Request) {
	// Retrieve the fetchSubscribe parameter from the query string
	fetchSubscribe := r.URL.Query().Get("fetchSubscribe")
	if fetchSubscribe == "" {
		http.Error(w, "fetchSubscribe parameter is required", http.StatusBadRequest)
		return
	}
	subGroup := r.URL.Query().Get("group")
	if subGroup == "" {
		http.Error(w, "group parameter is required", http.StatusBadRequest)
		return
	}
	// Create a new HTTP request with the desired URL
	req, err := http.NewRequest("GET", fetchSubscribe, nil)
	if err != nil {
		http.Error(w, "Failed to create HTTP request", http.StatusInternalServerError)
		return
	}
	ua := r.URL.Query().Get("ua")
	if ua != "" {
		// Set the User-Agent header
		req.Header.Set("User-Agent", ua)
	}

	module := r.URL.Query().Get("module")
	if module == "" {
		module = "tcp_connect"
	}

	remote := r.URL.Query().Get("remote")
	if remote == "" {
		remote = "http://www.google.com/generate_204"
	}

	// Create an HTTP client and send the request
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	response, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch data", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	bodyStr := string(body)
	fmt.Printf("Parsed %s Content:\n%s\n", subGroup, bodyStr)

	clash, err := parseProxies(body)
	if err != nil {
		http.Error(w, "Error parsing proxies", http.StatusInternalServerError)
		return
	}
	clash.Proxies = renameProxy(clash.Proxies, subGroup)
	xrayConfig := clash.XrayConfig()
	proxies := clash.Proxies
	xrayProxies := xrayConfig.OutboundConfigs

	filterNode := r.URL.Query().Get("filterNode") // 例如 "1,2,3"
	if filterNode != "" {
		proxies = filterProxies(proxies, filterNode, subGroup)
		xrayProxies = filterXrayProxies(xrayProxies, filterNode, subGroup)
	} else {
		proxies = removeIgnoreProxies(proxies, subGroup)
		xrayProxies = removeIgnoreXrayProxies(xrayProxies, subGroup)
	}
	marshal, err := json.Marshal(xrayProxies)
	fmt.Printf("Parsed xray Content:%s\n", marshal)
	proxiesJSON, err := convertProxiesToRemoteJSON(proxies, subGroup, module, remote, outboundNameCache)
	if err != nil {
		http.Error(w, "Error converting proxies to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(proxiesJSON); err != nil {
		http.Error(w, "Error writing proxies to JSON", http.StatusInternalServerError)
	}
	callGrpc(xrayProxies)
}

func renameProxy(proxies []share.ClashProxy, subGroup string) []share.ClashProxy {
	var renameProxies []share.ClashProxy
	for _, proxy := range proxies {
		formatName(&proxy, &subGroup)
		hash, err := getStructHash(&proxy)
		if err == nil {
			outboundNameCache.Delete(proxy.Name)
			prefix := getUniquePrefix(hash, outboundNameCache.Items())
			outboundNameCache.SetDefault(proxy.Name, prefix)
		}
		renameProxies = append(renameProxies, proxy)
	}
	return renameProxies
}

func callGrpc(proxies []conf.OutboundDetourConfig) {
	if !configGrpc || len(proxies) == 0 {
		return
	}
	grpcClient, err := grpc.NewClient("xray:10812", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to Xray API: %v", err)
	}
	defer grpcClient.Close()
	routeClient := routingService.NewRoutingServiceClient(grpcClient)
	handleClient := handlerService.NewHandlerServiceClient(grpcClient)
	ctx, c := dialAPIClient()
	defer c()
	for _, proxy := range proxies {
		tag := proxy.Tag
		headerProxyValue := getProxyValue(outboundNameCache, &tag)
		if _, found := outboundHashCache.Get(*headerProxyValue); !found {
			RuleCache.SetDefault(tag, &router.RoutingRule{
				RuleTag:    tag,
				Attributes: map[string]string{"proxy": *headerProxyValue},
				TargetTag:  &router.RoutingRule_Tag{Tag: tag},
			})
			outbound, _ := proxy.Build()
			adr := &handlerService.AddOutboundRequest{Outbound: outbound}
			fmt.Printf("Parsed AddOutboundRequest Content: %s\n", adr.String())
			_, err = handleClient.AddOutbound(ctx, adr)
			if err != nil {
				log.Printf("failed to perform AddOutbound: %s\n", err)
				d := &handlerService.RemoveOutboundRequest{Tag: tag}
				_, err = handleClient.RemoveOutbound(ctx, d)
				adr := &handlerService.AddOutboundRequest{Outbound: outbound}
				fmt.Printf("Parsed AddOutboundRequest Content: %s\n", adr.String())
				_, err = handleClient.AddOutbound(ctx, adr)
			}
			outboundHashCache.SetDefault(*headerProxyValue, true)
		}
	}

	if RuleCache.ItemCount() > 0 {
		var rules []*router.RoutingRule
		for _, v := range RuleCache.Items() {
			rules = append(rules, v.Object.(*router.RoutingRule))
		}
		routerConfig := &router.Config{
			Rule: rules,
		}
		ra := &routingService.AddRuleRequest{
			Config:       cserial.ToTypedMessage(routerConfig),
			ShouldAppend: false,
		}
		_, err = routeClient.AddRule(ctx, ra)
		if err != nil {
			log.Printf("failed to perform AddRule: %s\n", err)
		}
	}
}

func dialAPIClient() (ctx context.Context, close func()) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	close = func() {
		cancel()
	}
	return ctx, close
}

func dnsRequest(w http.ResponseWriter, r *http.Request) {

	var domains []string
	domainsParam := r.URL.Query().Get("domains")
	if domainsParam != "" {
		// 使用 "," 分割参数
		domains = strings.Split(domainsParam, ",")
	}

	// Retrieve the domain  parameter from the query string
	domainParam := r.URL.Query().Get("domain")
	if domainParam != "" {
		domains = append(domains, domainParam)
	}

	if len(domains) == 0 {
		http.Error(w, "domain or domains parameter is required", http.StatusBadRequest)
		return
	}
	sport := r.URL.Query().Get("port")
	if sport == "" {
		http.Error(w, "port  parameter is required", http.StatusBadRequest)
		return
	}
	port, err2 := strconv.Atoi(sport)
	if err2 != nil {
		http.Error(w, "port  parameter is required", http.StatusBadRequest)
		return
	}
	subGroup := r.URL.Query().Get("group")
	if subGroup == "" {
		http.Error(w, "group parameter is required", http.StatusBadRequest)
		return
	}
	module := r.URL.Query().Get("module")
	if module == "" {
		module = "tcp_connect"
	}
	var ecsIPs []string
	// 获取参数 `ids`
	ecsIPsParam := r.URL.Query().Get("ecsIPs") // 例如 "1,2,3"
	if ecsIPsParam != "" {
		// 使用 "," 分割参数
		ecsIPs = strings.Split(ecsIPsParam, ",")
	}
	var allIPMap = make(map[string]bool)   // 记录已解析的 IP，去重
	var ipMaps = make(map[string][]string) // 存储每个域名的唯一 IP
	var mutex sync.Mutex                   // 保护 allIPMap 共享资源
	var wg sync.WaitGroup                  // 控制并发
	for _, domain := range domains {
		wg.Add(1) // 增加等待的 goroutine 数量
		go func(domain string) {
			defer wg.Done() // 任务完成，减少计数

			var uniqueIPs []string
			_, innerIps := queryAliDNS(domain, ecsIPs)

			// 处理去重
			for _, ip := range innerIps {
				mutex.Lock() // 加锁，保证 allIPMap 并发安全
				if _, exists := allIPMap[ip]; !exists {
					uniqueIPs = append(uniqueIPs, ip)
					allIPMap[ip] = true
				}
				mutex.Unlock() // 解锁
			}

			// 保护 ipMaps 并发写入
			mutex.Lock()
			ipMaps[domain] = uniqueIPs
			mutex.Unlock()

		}(domain) // 传递参数，避免闭包问题
	}

	wg.Wait() // 等待所有 goroutine 完成

	fmt.Printf("IP addresses for %s\n", ipMaps)

	proxiesJSON, err := convertDnsToJSON(ipMaps, port, subGroup, module)
	if err != nil {
		http.Error(w, "Error converting proxies to JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(proxiesJSON); err != nil {
		http.Error(w, "Error writing proxies to JSON", http.StatusInternalServerError)
	}
}

// 解析域名，使用多个客户端 IP，并按照 clientIP 分组返回结果
// 解析域名，支持普通查询和按 `clientIP` 进行分组
func queryAliDNS(domain string, clientIPs []string) (map[string][]string, []string) {
	results := make(map[string][]string)

	// 如果 `clientIPs` 为空，则执行普通查询
	if len(clientIPs) == 0 {
		ips, err := dnsQuery(domain, dns.TypeA, "", false) // 不使用 EDNS
		if err != nil {
			fmt.Printf("Error querying Ali DNS: %v\n", err)
		} else {
			results["default"] = ips
		}
		return results, ips
	}

	// 并发查询多个 ECS 客户端 IP
	var wg sync.WaitGroup
	resultChan := make(chan struct {
		ClientIP string
		IPs      []string
	}, len(clientIPs))

	for _, ip := range clientIPs {
		wg.Add(1)
		go func(clientIP string) {
			defer wg.Done()
			ips, err := dnsQuery(domain, dns.TypeA, clientIP, true) // 启用 EDNS
			if err == nil {
				resultChan <- struct {
					ClientIP string
					IPs      []string
				}{ClientIP: clientIP, IPs: ips}
			} else {
				fmt.Printf("Error querying with IP %s: %v\n", clientIP, err)
			}
		}(ip)
	}

	// 等待所有请求完成
	wg.Wait()
	close(resultChan)

	// 存储结果（按 clientIP 分组）
	resultMap := make(map[string][]string)
	allIPMap := make(map[string]bool)
	// 转换去重的 IP 列表
	var uniqueIPs []string

	// 处理 channel 结果
	for res := range resultChan {
		// 提取所有的 key
		resultMap[res.ClientIP] = res.IPs
		subIPs := res.IPs
		for _, ip := range subIPs {
			// 检查是否存在 "ip"
			if _, exists := allIPMap[ip]; !exists {
				uniqueIPs = append(uniqueIPs, ip)
				allIPMap[ip] = true
			}
		}
	}

	return resultMap, uniqueIPs
}

// 获取本地 DNS 服务器（从 /etc/resolv.conf 读取）
func getLocalDNSServer() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		fmt.Printf("无法读取本地 DNS 配置: %v", err)
		return dnsServer
	}

	if len(config.Servers) > 0 {
		return config.Servers[0] + ":53" // 添加端口号
	}

	return dnsServer // 默认使用本地 DNS
}

// dnsQuery 执行 DNS 查询
func dnsQuery(domain string, qtype uint16, ecsIP string, useEDNS bool) ([]string, error) {
	dnsServer := dnsServer
	// 创建 DNS 消息
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype) // 设置查询问题
	m.RecursionDesired = true              // 递归查询
	// 添加 EDNS 客户端子网选项
	if useEDNS {
		edns := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{
				&dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        1, // 1 表示 IPv4，2 表示 IPv6
					SourceNetmask: 24,
					SourceScope:   0,
					Address:       net.ParseIP(ecsIP), // 传递 ECS 客户端 IP
				},
			},
		}
		m.Extra = append(m.Extra, edns)
	}
	// 创建 DNS 客户端
	c := &dns.Client{
		Timeout: 10 * time.Second,
	}
	// 发送查询请求
	r, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		log.Printf("DNS 查询失败: %v", err)
	}

	// 解析响应
	// 提取 IP 地址
	var ips []string
	for _, answer := range r.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

func queryAliDNSWithEDNS(domain string, ecsIP string, useEDNS bool) ([]string, error) {
	// 构造 DNS 消息
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA) // 查询 A 记录（IPv4 地址）
	// 添加 EDNS 客户端子网选项
	if useEDNS {
		edns := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{
				&dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        1, // 1 表示 IPv4，2 表示 IPv6
					SourceNetmask: 24,
					SourceScope:   0,
					Address:       net.ParseIP(ecsIP), // 传递 ECS 客户端 IP
				},
			},
		}
		msg.Extra = append(msg.Extra, edns)
	}

	// 将 DNS 消息编码为二进制格式
	binMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// 发送 HTTP POST 请求
	req, err := http.NewRequest("POST", aliDoHURL, bytes.NewReader(binMsg))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// 解码 DNS 响应消息
	response := new(dns.Msg)
	err = response.Unpack(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	// 提取 IP 地址
	var ips []string
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Retrieve the fetchSubscribe parameter from the query string
	fetchSubscribe := r.URL.Query().Get("fetchSubscribe")
	if fetchSubscribe == "" {
		http.Error(w, "fetchSubscribe parameter is required", http.StatusBadRequest)
		return
	}
	subGroup := r.URL.Query().Get("group")
	if subGroup == "" {
		http.Error(w, "group parameter is required", http.StatusBadRequest)
		return
	}
	// Create a new HTTP request with the desired URL
	req, err := http.NewRequest("GET", fetchSubscribe, nil)
	if err != nil {
		http.Error(w, "Failed to create HTTP request", http.StatusInternalServerError)
		return
	}
	ua := r.URL.Query().Get("ua")
	if ua != "" {
		// Set the User-Agent header
		req.Header.Set("User-Agent", ua)
	}

	module := r.URL.Query().Get("module")
	if module == "" {
		module = "tcp_connect"
	}

	// Create an HTTP client and send the request
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	response, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch data", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	//// Use fetchSubscribe as the URL for http.Get
	//response, err := http.Get(fetchSubscribe)
	//if err != nil {
	//	http.Error(w, "Failed to fetch data", http.StatusInternalServerError)
	//	return
	//}
	//defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Parsed %s Content:\n%s\n", subGroup, string(body))

	clash, err := parseProxies(body)
	if err != nil {
		http.Error(w, "Error parsing proxies", http.StatusInternalServerError)
		return
	}
	proxies := clash.Proxies
	proxies = removeIgnoreProxies(proxies, "")

	// 获取参数 `ids`
	ecsIPsParam := r.URL.Query().Get("ecsIPMaps") // 例如 "1,2,3"
	if ecsIPsParam != "" {
		// 使用 "," 分割参数
		ecsIPs := parseParamToEcsTag(ecsIPsParam)
		proxies = convert2DnsAndRemoveProxies(proxies, ecsIPs)
	} else {
		proxies = removeDuplicateProxies(proxies)
	}
	proxiesJSON, err := convertProxiesToJSON(proxies, subGroup, module)
	if err != nil {
		http.Error(w, "Error converting proxies to JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(proxiesJSON); err != nil {
		http.Error(w, "Error writing proxies to JSON", http.StatusInternalServerError)
	}
}

func removeIgnoreProxies(proxies []share.ClashProxy, group string) []share.ClashProxy {
	var uniqueProxies []share.ClashProxy

	for _, proxy := range proxies {
		if !containsKeyword(proxy.Name, ignoreKeyword) {
			uniqueProxies = append(uniqueProxies, proxy)
		}
	}
	return uniqueProxies
}

func removeIgnoreXrayProxies(proxies []conf.OutboundDetourConfig, group string) []conf.OutboundDetourConfig {
	var uniqueProxies []conf.OutboundDetourConfig

	for _, proxy := range proxies {
		if !containsKeyword(proxy.Tag, ignoreKeyword) {
			uniqueProxies = append(uniqueProxies, proxy)
		}
	}
	return uniqueProxies
}

func filterProxies(proxies []share.ClashProxy, node string, group string) []share.ClashProxy {
	var uniqueProxies []share.ClashProxy
	regex := regexp.MustCompile(node)
	for _, proxy := range proxies {
		if regexpMatch(proxy.Name, regex) {
			uniqueProxies = append(uniqueProxies, proxy)
		}
	}
	return uniqueProxies
}

func filterXrayProxies(proxies []conf.OutboundDetourConfig, node string, group string) []conf.OutboundDetourConfig {
	var uniqueProxies []conf.OutboundDetourConfig
	regex := regexp.MustCompile(node)
	for _, proxy := range proxies {
		proxy.Tag = strings.TrimSpace(proxy.Tag)
		if regexpMatch(proxy.Tag, regex) {
			uniqueProxies = append(uniqueProxies, proxy)
		}
	}
	return uniqueProxies
}

func parseParamToEcsTag(rawValue string) []EcsTag {
	// 提前声明 map 变量
	paramMap := make([]EcsTag, 0)

	// 解析 "先:1,安:2,你:3" 形式的数据
	pairs := strings.Split(rawValue, ",")
	for _, pair := range pairs {
		// 使用 `SplitN` 避免多个 `:` 导致错误
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			paramMap = append(paramMap, EcsTag{
				Name: kv[0],
				Ip:   kv[1],
			})
		}
	}
	return paramMap
}

func parseProxies(body []byte) (share.ClashYaml, error) {
	clash := share.ClashYaml{}
	err := yaml.Unmarshal(body, &clash)
	if err != nil {
		return clash, fmt.Errorf("error extracting proxies section: %w", err)
	}
	return clash, nil
}

// 判断输入是 IP 还是域名
func isIPAddress(input string) bool {
	return net.ParseIP(input) != nil
}

func convert2DnsAndRemoveProxies(proxies []share.ClashProxy, ecsIPMaps []EcsTag) []share.ClashProxy {
	var serverIndexMap sync.Map // 并发安全的 map
	serverIndexPreMap := make(map[string]int)
	serverServerMap := make(map[int]share.ClashProxy)
	var parseDnsProxies []share.ClashProxy // 结果存储
	var mutex sync.Mutex                   // 保护 parseDnsProxies
	var wg sync.WaitGroup                  // 并发控制
	for i, proxy := range proxies {
		if _, exists := serverIndexPreMap[proxy.Server]; !exists {
			serverIndexPreMap[proxy.Server] = i
			serverServerMap[i] = proxy
		}
	}
	for i, proxy := range serverServerMap {
		wg.Add(1) // 增加等待的 goroutine 数量
		go func(ii int, proxy2 share.ClashProxy) {
			defer wg.Done()
			if isIPAddress(proxy2.Server) {
				if _, exists := serverIndexMap.Load(proxy2.Server); !exists {
					serverIndexMap.Store(proxy2.Server, ii)
					mutex.Lock()
					parseDnsProxies = append(parseDnsProxies, proxy2) // Append proxy2 immediately when first encountered
					mutex.Unlock()
				}
			} else {
				if _, exists := serverIndexMap.Load(proxy2.Server); !exists {
					serverIndexMap.Store(proxy2.Server, ii)
					for _, ecsTag := range ecsIPMaps {
						clientIp := ecsTag.Ip
						clientName := ecsTag.Name
						_, ips := queryAliDNS(proxy2.Server, []string{clientIp})
						// 复制结构体并修改 Server
						for _, ip := range ips {
							copyProxy := proxy2
							copyProxy.Name = fmt.Sprintf("%s(%s-%s)", proxy2.Name, ip, clientName)
							copyProxy.Server = ip
							if _, subExists := serverIndexMap.Load(copyProxy.Server); !subExists {
								serverIndexMap.Store(copyProxy.Server, ii)
								mutex.Lock()
								parseDnsProxies = append(parseDnsProxies, copyProxy)
								mutex.Unlock()
							}
						}

					}
				}
			}
		}(i, proxy)
	}
	wg.Wait() // 等待所有 goroutine 完成
	return parseDnsProxies
}

func removeDuplicateProxies(proxies []share.ClashProxy) []share.ClashProxy {
	serverIndexMap := make(map[string]int)
	var uniqueProxies []share.ClashProxy

	for i, proxy := range proxies {
		if _, exists := serverIndexMap[proxy.Server]; !exists {
			serverIndexMap[proxy.Server] = i             // Store index of the first occurrence only
			uniqueProxies = append(uniqueProxies, proxy) // Append proxy immediately when first encountered
		}
	}

	return uniqueProxies
}

func convertProxiesToJSON(proxies []share.ClashProxy, group string, module string) ([]byte, error) {
	proxiesJSON := make([]ProxyJSON, len(proxies))
	for i, proxy := range proxies {
		proxiesJSON[i] = ProxyJSON{
			Targets: []string{fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)},
			Labels: map[string]string{
				"instance":           proxy.Name,
				"server":             proxy.Server,
				"group":              group,
				"module":             module,
				"header_proxy_key":   "proxy",
				"header_proxy_value": proxy.Name,
			},
		}
	}

	return json.MarshalIndent(proxiesJSON, "", "  ")
}

func convertProxiesToRemoteJSON(proxies []share.ClashProxy, group string, module string, remote string, nameCache *cache.Cache) ([]byte, error) {
	proxiesJSON := make([]ProxyJSON, len(proxies))
	for i, proxy := range proxies {
		headerProxyValue := getProxyValue(nameCache, &proxy.Name)
		proxiesJSON[i] = ProxyJSON{
			Targets: []string{remote},
			Labels: map[string]string{
				"instance":           proxy.Name,
				"server":             proxy.Server,
				"group":              group,
				"module":             module,
				"remote":             remote,
				"header_proxy_key":   "proxy",
				"header_proxy_value": *headerProxyValue,
			},
		}
	}
	return json.MarshalIndent(proxiesJSON, "", "  ")
}

func getProxyValue(nameCache *cache.Cache, name *string) *string {
	var headerProxyValue *string
	if x, found := nameCache.Get(*name); found {
		if u, ok := x.(string); ok {
			headerProxyValue = &u
		} else {
			headerProxyValue = name
		}
	} else {
		headerProxyValue = name
	}
	return headerProxyValue
}

func convertDnsToJSON(ipMaps map[string][]string, port int, group string, module string) ([]byte, error) {
	var proxiesJSON []ProxyJSON
	for domain, ips := range ipMaps {
		for _, ip := range ips {
			instance := fmt.Sprintf("%s(%s):%d", domain, ip, port)
			proxiesJSON = append(proxiesJSON, ProxyJSON{
				Targets: []string{fmt.Sprintf("%s:%d", ip, port)},
				Labels: map[string]string{
					"instance": instance,
					"domain":   domain,
					"group":    group,
					"module":   module,
					"ip":       ip,
				},
			})
		}
	}
	return json.MarshalIndent(proxiesJSON, "", "  ")
}

// containsKeyword 检查字符串是否包含关键字
func containsKeyword(s string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(s, keyword) { // 判断是否包含关键字
			return true
		}
	}
	return false
}

// containsKeyword 检查字符串是否包含关键字
func regexpMatch(s string, regex *regexp.Regexp) bool {
	return regex.MatchString(s)
}
