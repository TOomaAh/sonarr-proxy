package main

import (
	"bufio" // To read the client's request in the tunnel
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp" // Added for replaceSerieName
	"strings"
	"sync"
	"text/template"
	"time"
)

//go:embed index.html
var adminTemplate embed.FS

const (
	SONARR_HOST                 = "localhost:8989" // Host without protocol for the proxy
	PROXY_PORT                  = ":8990"
	MAPPINGS_FILE               = "series_mappings.json"
	SERVICES_SONARR_TV_BASE_URL = "https://services.sonarr.tv" // Correct URL for scenemapping
	SCENEMAPPING_CACHE_DURATION = 1 * time.Hour                // Refresh cache every hour
	INTERCEPTION_RULES_FILE     = "interception_rules.json"    // Name of the rules file
)

var tlsCert tls.Certificate
var errCertLoad error

// Structures (SeriesMapping, InterceptionRule) remain the same
type SeriesMapping struct {
	TvdbId   int    `json:"tvdbId"`
	Official string `json:"official"`
	Tracker  string `json:"tracker"`
	Season   int    `json:"season"` // -1 for all seasons
	Note     string `json:"note,omitempty"`
}

type SonarrSeriesMapping struct { // Note: This struct is defined but not used in the provided snippet.
	SearchTitle string `json:"searchTitle"`
	Title       string `json:"title"`
	MappingId   int    `json:"mappingId"` // Note: Sonarr's mappingId is usually a string like "s-..."
	Season      int    `json:"season"`
	TvdbId      int    `json:"tvdbId"`
}

type InterceptionRule struct {
	Name        string `json:"name"`
	Method      string `json:"method"`
	PathPattern string `json:"pathPattern"`
	BodyType    string `json:"bodyType"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
}

var (
	seriesMappings = make(map[string]SeriesMapping)
	mappingsMutex  sync.RWMutex
)

var (
	interceptionRules = make(map[string]InterceptionRule)
	rulesMutex        sync.RWMutex
)

var (
	logBuffer []string
	logMutex  sync.RWMutex
)

// Cache for scenemapping
var (
	sceneMappingCache      []byte
	sceneMappingCacheMutex sync.RWMutex
	lastCacheUpdateTime    time.Time
)

func loadMitmCertificate() {
	// These paths are relative to the execution directory of your Go application.
	// Ensure these files are present there.
	certPath := "services.sonarr.tv.crt" // The public certificate for services.sonarr.tv
	keyPath := "services.sonarr.tv.key"  // The UNENCRYPTED private key for services.sonarr.tv

	// Attempt to load the key/certificate pair
	loadedCert, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
	if loadErr != nil {
		// If loading fails, store the error and log.
		// The global errCertLoad will be checked before using tlsCert.
		errCertLoad = fmt.Errorf("❌ Error loading MitM key/certificate pair ('%s', '%s'): %w", certPath, keyPath, loadErr)
		log.Printf("%v", errCertLoad) // Use log.Printf for the wrapped error
		// Do not assign to tlsCert if an error occurred
		return
	}

	// Additional check (generally not necessary if LoadX509KeyPair succeeds, but harmless)
	if loadedCert.PrivateKey == nil {
		errCertLoad = fmt.Errorf("❌ Private key from loaded pair ('%s', '%s') is nil, even if LoadX509KeyPair returned no direct error", certPath, keyPath)
		log.Printf("%v", errCertLoad)
		return
	}

	// If everything went well, assign to the global variable
	tlsCert = loadedCert
	errCertLoad = nil // Ensure errCertLoad is nil if loading succeeded
	addLog(fmt.Sprintf("🔑 MitM certificate for '%s' loaded successfully from '%s' and '%s'.", "services.sonarr.tv", certPath, keyPath))
}

// The serveScenemappingViaTls function we defined previously
func serveScenemappingViaTls(clientConn net.Conn, originalHost string) {
	defer clientConn.Close() // Ensure the client connection is closed at the end

	if errCertLoad != nil {
		addLog(fmt.Sprintf("❌ MitM certificate not loaded for %s, aborting TLS attempt.", originalHost))
		// Not much can be done here as the client expects a TLS handshake.
		// Closing the connection is the only clean option.
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// You might want to set MinVersion, CipherSuites, etc.
		// MinVersion: tls.VersionTLS12,
	}

	addLog(fmt.Sprintf("🤝 Attempting MitM TLS handshake with %s (for %s)...", clientConn.RemoteAddr(), originalHost))
	tlsServerConn := tls.Server(clientConn, tlsConfig) // Wrap the client connection with our TLS server config

	// Perform the TLS handshake. This is a blocking call.
	// Setting a timeout on the handshake itself might be a good idea
	// by wrapping tlsServerConn.Handshake() in a goroutine with a select and a time.After,
	// but a direct call is simpler to start with.
	// tlsServerConn.SetDeadline(time.Now().Add(10 * time.Second)) // Timeout for the handshake
	err := tlsServerConn.Handshake()
	// tlsServerConn.SetDeadline(time.Time{}) // Remove the deadline after the handshake

	if err != nil {
		addLog(fmt.Sprintf("❌ MitM TLS handshake error with %s: %v", clientConn.RemoteAddr(), err))
		// Common causes:
		// 1. The client does not trust the CA that signed your certificate.
		// 2. CipherSuite or TLS version incompatibility.
		// 3. The client closed the connection during the handshake.
		return
	}
	// defer tlsServerConn.CloseWrite() // To send a TLS close_notify, good practice but can be omitted for simplicity.
	// The global clientConn.Close() should suffice.
	addLog(fmt.Sprintf("✅ MitM TLS handshake successful with %s. State: CipherSuite %s, Version %s",
		clientConn.RemoteAddr(), tls.CipherSuiteName(tlsServerConn.ConnectionState().CipherSuite), tlsVersionToString(tlsServerConn.ConnectionState().Version)))

	// Now, read the HTTP request over the decrypted TLS connection
	err = tlsServerConn.SetReadDeadline(time.Now().Add(15 * time.Second)) // Timeout to read the HTTP request
	if err != nil {
		addLog(fmt.Sprintf("Error SetReadDeadline for tlsServerConn %s (after handshake): %v", tlsServerConn.RemoteAddr(), err))
		return
	}

	bufferedReader := bufio.NewReader(tlsServerConn)
	httpRequest, err := http.ReadRequest(bufferedReader)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			addLog(fmt.Sprintf("⏳ Timeout waiting for HTTP request (decrypted) from %s", clientConn.RemoteAddr()))
		} else if err == io.EOF {
			addLog(fmt.Sprintf("ℹ️ Connection (TLS) closed by %s before sending HTTP request", clientConn.RemoteAddr()))
		} else {
			addLog(fmt.Sprintf("❌ Error reading HTTP request (decrypted) from %s: %v", clientConn.RemoteAddr(), err))
		}
		return
	}
	// Important: consume and close the request body to allow connection reuse
	// if the client was using HTTP/1.1 keep-alive (although we respond with Connection: close).
	if httpRequest.Body != nil {
		io.Copy(io.Discard, httpRequest.Body)
		httpRequest.Body.Close()
	}

	addLog(fmt.Sprintf("📄 HTTP request (decrypted) received from %s: %s %s", clientConn.RemoteAddr(), httpRequest.Method, httpRequest.URL.Path))

	// ... (the rest of your logic to serve from cache or return an error,
	// using httpRequest.Method, httpRequest.URL.Path and writing the response to tlsServerConn)
	// ... as in the previous response
	if httpRequest.Method == "GET" && httpRequest.URL.Path == "/v1/scenemapping" {
		sceneMappingCacheMutex.RLock()
		cachedData := sceneMappingCache
		isCachePopulated := len(cachedData) > 0
		var lastUpdate time.Time
		if isCachePopulated { // Only read lastCacheUpdateTime if the cache is not empty
			lastUpdate = lastCacheUpdateTime
		}
		sceneMappingCacheMutex.RUnlock() // Unlock as soon as possible

		isCacheFresh := isCachePopulated && time.Since(lastUpdate) < (SCENEMAPPING_CACHE_DURATION+5*time.Minute)

		if isCachePopulated && isCacheFresh {
			addLog(fmt.Sprintf("📦 Serving /v1/scenemapping from cache (via MitM TLS) for %s", clientConn.RemoteAddr()))
			response := http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1, ProtoMinor: 1,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(cachedData)),
				ContentLength: int64(len(cachedData)),
			}
			response.Header.Set("Content-Type", "application/json; charset=utf-8")
			response.Header.Set("Content-Length", fmt.Sprintf("%d", len(cachedData)))
			response.Header.Set("Connection", "close") // Important to close the connection after

			err = response.Write(tlsServerConn)
			if err != nil {
				addLog(fmt.Sprintf("❌ Error sending cache response (via MitM TLS) to %s: %v", clientConn.RemoteAddr(), err))
			} else {
				addLog(fmt.Sprintf("✅ Cache response (via MitM TLS) sent to %s", clientConn.RemoteAddr()))
			}
		} else {
			var errMsg string
			if !isCachePopulated {
				errMsg = "Scene mapping cache is not populated."
				addLog(fmt.Sprintf("⚠️ Scene mapping cache empty, serving 503 (via MitM TLS) for %s", clientConn.RemoteAddr()))
			} else { // Implies !isCacheFresh
				errMsg = "Scene mapping cache is outdated."
				addLog(fmt.Sprintf("⚠️ Scene mapping cache outdated (last update: %s), serving 503 (via MitM TLS) for %s", lastUpdate.Format(time.RFC3339), clientConn.RemoteAddr()))
			}

			errorResponse := http.Response{
				StatusCode: http.StatusServiceUnavailable,
				ProtoMajor: 1, ProtoMinor: 1,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader(errMsg)),
				ContentLength: int64(len(errMsg)),
			}
			errorResponse.Header.Set("Content-Type", "text/plain; charset=utf-8")
			errorResponse.Header.Set("Connection", "close")

			errWrite := errorResponse.Write(tlsServerConn)
			if errWrite != nil {
				addLog(fmt.Sprintf("❌ Error sending 503 response (via MitM TLS) to %s: %v", clientConn.RemoteAddr(), errWrite))
			}
		}
	} else {
		addLog(fmt.Sprintf("➡️ Request (%s %s) for %s (from %s) not handled by cache. Attempting relay...",
			httpRequest.Method, httpRequest.URL.Path, originalHost, clientConn.RemoteAddr()))

		// Step 1: Establish an outgoing TLS connection to the real originalHost server
		// Use a standard dialer for the TCP connection, then perform a client TLS handshake.
		// originalHost is e.g., "services.sonarr.tv:443"
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		targetUpstreamConn, err := dialer.Dial("tcp", originalHost)
		if err != nil {
			addLog(fmt.Sprintf("❌ TCP connection error to remote host %s for relay: %v", originalHost, err))
			// Send a 502 Bad Gateway error to the client
			sendHttpErrorResponse(tlsServerConn, http.StatusBadGateway, "Failed to connect to upstream server")
			return
		}
		defer targetUpstreamConn.Close()

		// Configure the client TLS connection
		// To connect to a real public server, we typically use the default config
		// which verifies the server's certificate against system root CAs.
		// We must specify ServerName so the remote server knows which certificate to present (SNI).
		hostnameOnly, _, _ := net.SplitHostPort(originalHost) // Extracts "services.sonarr.tv" from "services.sonarr.tv:443"

		tlsClientConfig := &tls.Config{
			ServerName: hostnameOnly,
			// InsecureSkipVerify: false, // Important: do not set to true in production!
			// MinVersion: tls.VersionTLS12,
		}

		addLog(fmt.Sprintf("🤝 Attempting client TLS handshake to %s...", originalHost))
		targetTlsConn := tls.Client(targetUpstreamConn, tlsClientConfig)

		err = targetTlsConn.Handshake()
		if err != nil {
			addLog(fmt.Sprintf("❌ Client TLS handshake error to %s: %v", originalHost, err))
			sendHttpErrorResponse(tlsServerConn, http.StatusBadGateway, "TLS handshake with upstream server failed")
			return
		}
		defer targetTlsConn.Close() // Ensure the outgoing TLS connection is closed
		addLog(fmt.Sprintf("✅ Client TLS handshake to %s successful.", originalHost))

		// Step 2: Write the original request (httpRequest) that we received from Sonarr
		// to the outgoing TLS connection (targetTlsConn).
		// httpRequest.RequestURI must be empty for a client request.
		// httpRequest.URL.Scheme and httpRequest.URL.Host should be set if not already.
		// However, http.Request.Write expects it to be a server request.
		// For a client request, it's safer to rebuild or use http.Client.
		// But here, we already have the parsed request, we can try to write it.
		// We need to ensure the URL is relative for the request written to the remote server.
		// httpRequest.URL.Scheme = ""
		// httpRequest.URL.Host = ""
		// To avoid issues with Host header vs URL.Host, etc., let's rebuild the request
		// for the remote server, keeping the body, method, and headers.

		// Rewrite the request for the remote server.
		// The original httpRequest was read from the client.
		// To send it to another server, ensure the Host header is correct, etc.
		// The simplest is to let the Write method of http.Request handle serialization.
		// It expects the URL to be relative for non-proxy requests.
		// Ensure the Host header is indeed that of originalHost.
		httpRequest.Host = hostnameOnly // or originalHost if you want to include the port

		addLog(fmt.Sprintf("📤 Sending request (%s %s) to remote server %s...", httpRequest.Method, httpRequest.URL.Path, originalHost))
		err = httpRequest.Write(targetTlsConn) // Write the HTTP request (already parsed) over the outgoing TLS connection
		if err != nil {
			addLog(fmt.Sprintf("❌ Error writing HTTP request to %s: %v", originalHost, err))
			sendHttpErrorResponse(tlsServerConn, http.StatusBadGateway, "Failed to send request to upstream server")
			return
		}

		// Step 3: Directly relay the response from the remote server (targetTlsConn)
		// to the client (tlsServerConn)
		addLog(fmt.Sprintf("📥 Directly relaying response bytes from %s to %s...", originalHost, clientConn.RemoteAddr()))

		// Copy data from the outgoing TLS connection to the incoming TLS connection
		bytesCopied, err := io.Copy(tlsServerConn, targetTlsConn) // Warning: no header manipulation here
		if err != nil {
			// Ignore EOF errors that can occur if the remote connection closes normally.
			// Other errors might be more serious.
			if err != io.EOF {
				addLog(fmt.Sprintf("❌ Error during io.Copy of response from %s to client %s after %d bytes: %v",
					originalHost, clientConn.RemoteAddr(), bytesCopied, err))
			}
		}
		addLog(fmt.Sprintf("✅ Direct response relay finished. %d bytes copied from %s to client %s.",
			bytesCopied, originalHost, clientConn.RemoteAddr()))

		// Note: With direct io.Copy, headers like Connection: close or removal of hopHeaders
		// are not explicitly managed. Behavior will depend on what the remote server sends
		// and how the client interprets it.
		// Closing connections (targetTlsConn.Close() and the defer clientConn.Close())
		// will handle the end of the stream.
	}
}

// Utility function to send a simple HTTP error response over a net.Conn (or tls.Conn)
func sendHttpErrorResponse(conn net.Conn, statusCode int, message string) { // Changed io.Writer to net.Conn for RemoteAddr
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Error" // Default if statusCode is unknown
	}
	responseBody := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, len(message), message)
	_, err := conn.Write([]byte(responseBody))
	if err != nil {
		addLog(fmt.Sprintf("❌ Error sending HTTP error response %d to %s: %v", statusCode, conn.RemoteAddr(), err))
	} else {
		addLog(fmt.Sprintf("✅ HTTP error response %d sent to %s: %s", statusCode, conn.RemoteAddr(), message))
	}
}

// Utility function to convert TLS version to string
func tlsVersionToString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// Add a log
func addLog(message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	timestampedMessage := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05.000"), message)
	logBuffer = append(logBuffer, timestampedMessage)
	const maxLogBufferSize = 200 // Increased for more logs
	if len(logBuffer) > maxLogBufferSize {
		logBuffer = logBuffer[1:]
	}
	log.Print(timestampedMessage)
}

// Function to refresh the scenemapping cache
func updateSceneMappingCache() {
	addLog("🔄 Attempting to refresh scenemapping cache...")
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", SERVICES_SONARR_TV_BASE_URL+"/v1/scenemapping", nil)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error creating request for scenemapping cache: %v", err))
		return
	}
	req.Header.Set("User-Agent", "Sonarr SceneMapping Proxy/1.0") // Good practice

	resp, err := client.Do(req)
	if err != nil {
		addLog(fmt.Sprintf("❌ HTTP request error for scenemapping cache: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		addLog(fmt.Sprintf("❌ Non-OK status (%d) for scenemapping cache. Response: %s", resp.StatusCode, string(bodyBytes)))
		return
	}

	originalBody, err := io.ReadAll(resp.Body)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error reading body for scenemapping cache: %v", err))
		return
	}

	var remoteMappings []map[string]interface{}
	if err := json.Unmarshal(originalBody, &remoteMappings); err != nil {
		addLog(fmt.Sprintf("❌ Error unmarshalling original JSON for scenemapping cache: %v. Preview: %s", err, string(originalBody[:min(200, len(originalBody))])))
		return
	}
	addLog(fmt.Sprintf("ℹ️ %d scenemappings received from %s", len(remoteMappings), SERVICES_SONARR_TV_BASE_URL))

	// Add our local mappings
	mappingsMutex.RLock()
	addedCount := 0
	// The `sonarrSeriesMappings` slice creation and loop was a bit convoluted.
	// Let's directly use `seriesMappings` and the `mapKey` for ID generation.
	for mapKey, ourMapping := range seriesMappings {
		// Check if a functionally similar mapping already exists
		exists := false
		for _, remoteMap := range remoteMappings {
			if remoteTvdbId, okTvdb := remoteMap["tvdbId"].(float64); okTvdb { // JSON decodes numbers to float64
				if int(remoteTvdbId) == ourMapping.TvdbId {
					// Sonarr uses "searchTitle" for the tracker name in its scene mappings
					if remoteSearchTitle, okScene := remoteMap["searchTitle"].(string); okScene && remoteSearchTitle == ourMapping.Tracker {
						// Sonarr uses "season" for season number in its scene mappings
						if remoteSeason, okSeason := remoteMap["season"].(float64); okSeason && int(remoteSeason) == ourMapping.Season {
							exists = true
							break
						}
					}
				}
			}
		}

		if !exists {
			localMappingId := fmt.Sprintf("localproxy-%s", mapKey)
			customMapping := map[string]interface{}{
				"mappingId":   localMappingId, // Unique ID for the mapping
				"tvdbId":      ourMapping.TvdbId,
				"title":       ourMapping.Official, // The official series title
				"searchTitle": ourMapping.Tracker,  // The name used on trackers/scene
				"season":      ourMapping.Season,   // The season number (-1 for all)
			}
			remoteMappings = append(remoteMappings, customMapping) // Add to the list
			addedCount++
			addLog(fmt.Sprintf("➕ Adding local scene mapping: ID '%s', Series '%s' (TVDB: %d), Tracker '%s', Season %d",
				localMappingId, ourMapping.Official, ourMapping.TvdbId, ourMapping.Tracker, ourMapping.Season))
		}
	}
	mappingsMutex.RUnlock()

	modifiedBody, err := json.Marshal(remoteMappings)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error marshalling modified JSON for scenemapping cache: %v", err))
		return
	}

	sceneMappingCacheMutex.Lock()
	sceneMappingCache = modifiedBody
	lastCacheUpdateTime = time.Now()
	sceneMappingCacheMutex.Unlock()
	addLog(fmt.Sprintf("✅ Scenemapping cache refreshed. %d remote mappings, %d added locally. Total: %d. Size: %d bytes", len(remoteMappings)-addedCount, addedCount, len(remoteMappings), len(modifiedBody)))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Handler for CONNECT requests
func connectHandler(w http.ResponseWriter, r *http.Request) {
	addLog(fmt.Sprintf("🔗 CONNECT request to: %s from %s", r.Host, r.RemoteAddr))

	// Check if the target is services.sonarr.tv (port 443 is implicit for CONNECT HTTPS)
	if strings.HasPrefix(r.Host, "services.sonarr.tv") {
		handleServicesSonarrTvConnect(w, r) // Call the specific function
		return
	}

	// For other connections, normal tunnel
	handleNormalConnection(w, r)
}

func handleServicesSonarrTvConnect(w http.ResponseWriter, r *http.Request) {
	originalHost := r.Host // Save for logs, etc.
	addLog(fmt.Sprintf("🎯 Intercepting CONNECT for %s (potential scenemapping)", originalHost))

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		addLog("❌ Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack() // _, clientReadWriter := hijacker.Hijack()
	if err != nil {
		addLog(fmt.Sprintf("❌ Hijacking error for %s: %v", originalHost, err))
		// http.Error will no longer work as the connection is hijacked.
		// You can try to write a raw error response to clientConn if possible, or just close.
		if clientConn != nil {
			clientConn.Close()
		}
		return
	}
	// Important: Do not close clientConn here, the goroutine will handle it.

	// Step 1: Respond 200 OK to the client to tell it the tunnel is "established"
	// (even if it's a tunnel to our own MitM TLS server)
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		addLog(fmt.Sprintf("❌ Error sending '200 Connection established' to %s (for %s): %v", clientConn.RemoteAddr(), originalHost, err))
		clientConn.Close()
		return
	}
	addLog(fmt.Sprintf("✅ '200 Connection established' sent to %s. Starting MitM TLS session...", clientConn.RemoteAddr()))

	// Step 2: Launch the goroutine that will handle the TLS handshake and MitM logic
	// This is where we call serveScenemappingViaTls
	go serveScenemappingViaTls(clientConn, originalHost)
}

// For other CONNECT requests, normal tunnel
func handleNormalConnection(w http.ResponseWriter, r *http.Request) {
	addLog(fmt.Sprintf("🔗 Normal tunnel for: %s from %s", r.Host, r.RemoteAddr))
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error connecting to %s for normal tunnel: %v", r.Host, err))
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK) // Indicate to the client that the tunnel is ready

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		addLog("❌ Hijacking not supported for normal tunnel")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close() // Important to close the connection established to the destination
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		addLog(fmt.Sprintf("❌ Hijacking error for normal tunnel to %s: %v", r.Host, err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		destConn.Close()
		return
	}
	addLog(fmt.Sprintf("✅ Normal tunnel established between %s and %s", clientConn.RemoteAddr(), r.Host))

	// Goroutines to transfer data in both directions
	go transfer(destConn, clientConn, fmt.Sprintf("client (%s) -> server (%s)", clientConn.RemoteAddr(), r.Host))
	go transfer(clientConn, destConn, fmt.Sprintf("server (%s) -> client (%s)", r.Host, clientConn.RemoteAddr()))
}

func transfer(destination io.WriteCloser, source io.ReadCloser, id string) {
	defer destination.Close()
	defer source.Close()
	// addLog(fmt.Sprintf("📤 Starting transfer %s", id))
	bytesCopied, err := io.Copy(destination, source)
	if err != nil {
		// Ignore "use of closed network connection" errors which are normal at the end of a tunnel
		if !strings.Contains(err.Error(), "use of closed network connection") && err != io.EOF {
			addLog(fmt.Sprintf("❌ Error during transfer %s after %d bytes: %v", id, bytesCopied, err))
		}
	}
	// addLog(fmt.Sprintf("🔚 Transfer finished %s, %d bytes copied", id, bytesCopied))
}

// --- Start of functions you already had and are still useful ---
// (loadMappings, saveMappings, loadRules, saveRules, adminHandler, addMappingHandler, etc.)
// (httpProxyHandler, modifyRequestBody, modifyResponseBody, replaceSerieName, shouldIntercept)
// Ensure they are present and correct.
// I'm including slightly modified/cleaned versions of some.

// Save mappings to file
func saveMappings() {
	mappingsMutex.Lock()
	defer mappingsMutex.Unlock()
	file, err := os.Create(MAPPINGS_FILE)
	if err != nil {
		addLog(fmt.Sprintf("Error creating mappings file: %v", err))
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // For readable JSON
	if err := encoder.Encode(seriesMappings); err != nil {
		addLog(fmt.Sprintf("Error saving mappings: %v", err))
	} else {
		addLog(fmt.Sprintf("💾 Mappings saved to %s", MAPPINGS_FILE))
	}
}

// Load mappings from file
func loadMappings() {
	mappingsMutex.Lock()
	defer mappingsMutex.Unlock()

	file, err := os.Open(MAPPINGS_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			addLog(fmt.Sprintf("Mappings file '%s' not found. It will be created if mappings are added.", MAPPINGS_FILE))
		} else {
			addLog(fmt.Sprintf("Error opening mappings file '%s': %v", MAPPINGS_FILE, err))
		}
		return
	}
	defer file.Close()

	// Initialize seriesMappings to avoid nil panic if the file is empty but exists
	seriesMappings = make(map[string]SeriesMapping)
	if err := json.NewDecoder(file).Decode(&seriesMappings); err != nil {
		// If the file is empty, Decode returns EOF, which is ok.
		if err != io.EOF {
			addLog(fmt.Sprintf("Error reading/decoding mappings from '%s': %v", MAPPINGS_FILE, err))
			seriesMappings = make(map[string]SeriesMapping) // Reset in case of decoding error
		}
	}
	addLog(fmt.Sprintf("📋 Mappings loaded from '%s': %d entries", MAPPINGS_FILE, len(seriesMappings)))
}

// Save interception rules
func saveRules() {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()
	file, err := os.Create(INTERCEPTION_RULES_FILE)
	if err != nil {
		addLog(fmt.Sprintf("Error creating rules file '%s': %v", INTERCEPTION_RULES_FILE, err))
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(interceptionRules); err != nil {
		addLog(fmt.Sprintf("Error saving rules to '%s': %v", INTERCEPTION_RULES_FILE, err))
	} else {
		addLog(fmt.Sprintf("💾 Rules saved to %s", INTERCEPTION_RULES_FILE))
	}
}

// Load interception rules
func loadRules() {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	file, err := os.Open(INTERCEPTION_RULES_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			addLog(fmt.Sprintf("Rules file '%s' not found, creating with default rules.", INTERCEPTION_RULES_FILE))
			// Initialize with default rules if the file doesn't exist
			interceptionRules = make(map[string]InterceptionRule) // Ensure it's initialized
			interceptionRules["log_sonarr_releases"] = InterceptionRule{
				Name:        "Log Sonarr Release Results",
				Method:      "GET",
				PathPattern: "/api/v3/release", // Sonarr API endpoint for release search results
				BodyType:    "response",
				Action:      "log",
				Enabled:     true,
			}
			interceptionRules["modify_sonarr_search_terms"] = InterceptionRule{
				Name:        "Modify Sonarr Search Terms",
				Method:      "POST",
				PathPattern: "/api/v3/search", // Sonarr API endpoint for initiating a search
				BodyType:    "request",
				Action:      "modify",
				Enabled:     true,
			}
			interceptionRules["modify_sonarr_series_alttitles"] = InterceptionRule{
				Name:        "Modify Sonarr Series Alternate Titles",
				Method:      "GET",
				PathPattern: "/api/v3/series", // Sonarr API endpoint for series details
				BodyType:    "response",
				Action:      "modify",
				Enabled:     true,
			}
			// No need for a scenemapping rule here, it's handled by the cache.
			saveRules() // Save default rules to create the file
		} else {
			addLog(fmt.Sprintf("Error opening rules file '%s': %v", INTERCEPTION_RULES_FILE, err))
		}
		return
	}
	defer file.Close()

	interceptionRules = make(map[string]InterceptionRule) // Initialize
	if err := json.NewDecoder(file).Decode(&interceptionRules); err != nil {
		if err != io.EOF { // EOF is ok for an empty JSON file (an empty map)
			addLog(fmt.Sprintf("Error reading/decoding rules from '%s': %v", INTERCEPTION_RULES_FILE, err))
			interceptionRules = make(map[string]InterceptionRule) // Reset in case of error
		}
	}
	addLog(fmt.Sprintf("📏 Interception rules loaded from '%s': %d entries", INTERCEPTION_RULES_FILE, len(interceptionRules)))
}

// Replace series name according to mapping
func replaceSerieName(term string) string {
	mappingsMutex.RLock()
	defer mappingsMutex.RUnlock()

	// For case-insensitive replacement, regex is more robust.
	// Iterate over mappings and build regex if necessary.
	for _, mapping := range seriesMappings {
		// (?i) for case-insensitive, QuoteMeta to escape special characters in mapping.Official
		regexPattern := "(?i)" + regexp.QuoteMeta(mapping.Official)
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			addLog(fmt.Sprintf("Error compiling regex for mapping '%s': %v", mapping.Official, err))
			continue // Skip to the next mapping
		}
		if re.MatchString(term) {
			// Replacing while keeping original case is complex.
			// Simplest is to replace with mapping.Tracker as is.
			addLog(fmt.Sprintf("🔄 Term replacement: '%s' found in '%s', replaced with '%s'", mapping.Official, term, mapping.Tracker))
			return re.ReplaceAllString(term, mapping.Tracker)
		}
	}
	return term
}

// Check if a request should be intercepted
func shouldIntercept(method, path string) (InterceptionRule, bool) {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	normalizedPath := strings.ToLower(path)
	normalizedMethod := strings.ToUpper(method)

	for _, rule := range interceptionRules {
		if !rule.Enabled {
			continue
		}
		if rule.Method != "" && rule.Method != normalizedMethod {
			continue
		}
		if rule.PathPattern != "" && !strings.Contains(normalizedPath, strings.ToLower(rule.PathPattern)) {
			continue
		}
		return rule, true
	}
	return InterceptionRule{}, false
}

// Function to modify HTTP request body (not CONNECT)
func modifyRequestBody(body []byte, r *http.Request) ([]byte, bool) {
	rule, shouldProcess := shouldIntercept(r.Method, r.URL.Path)
	if !shouldProcess || (rule.BodyType != "request" && rule.BodyType != "both") {
		return body, false
	}

	addLog(fmt.Sprintf("🔍 Intercepting HTTP REQUEST: %s %s (rule: %s, host: %s)", r.Method, r.URL.String(), rule.Name, r.Host))

	switch rule.Action {
	case "log":
		addLog(fmt.Sprintf("📝 HTTP REQUEST body (log): %s", string(body)))
		return body, false

	case "modify":
		// Example: Modify search term for Sonarr
		// Note: Ensure r.Host matches your Sonarr (SONARR_HOST)
		// or the rule is specific enough (PathPattern).
		if strings.EqualFold(r.Method, "POST") && strings.Contains(strings.ToLower(r.URL.Path), "/api/v3/search") {
			var searchData map[string]interface{}
			if err := json.Unmarshal(body, &searchData); err == nil {
				if term, exists := searchData["term"].(string); exists {
					originalTerm := term
					modifiedTerm := replaceSerieName(term)
					if modifiedTerm != originalTerm {
						searchData["term"] = modifiedTerm
						if modifiedBody, err := json.Marshal(searchData); err == nil {
							addLog(fmt.Sprintf("🔄 HTTP REQUEST body /api/v3/search modified: '%s' -> '%s'", originalTerm, modifiedTerm))
							return modifiedBody, true
						}
					}
				}
			}
		}
		addLog(fmt.Sprintf("ℹ️ 'modify' action for HTTP REQUEST %s %s, but no specific modification applied.", r.Method, r.URL.Path))

	case "block":
		addLog(fmt.Sprintf("🚫 HTTP REQUEST blocked by rule '%s': %s %s", rule.Name, r.Method, r.URL.String()))
		// For actual blocking, httpProxyHandler should return an HTTP error.
		// Here, we can only decide not to forward the body or return an empty body.
		return []byte("Blocked by proxy rule."), true // Example blocking body
	}
	return body, false
}

// Function to modify HTTP response body (not CONNECT)
func modifyResponseBody(body []byte, resp *http.Response) ([]byte, bool) {
	req := resp.Request
	rule, shouldProcess := shouldIntercept(req.Method, req.URL.Path)
	if !shouldProcess || (rule.BodyType != "response" && rule.BodyType != "both") {
		return body, false
	}

	addLog(fmt.Sprintf("🔍 Intercepting HTTP RESPONSE: %s %s (rule: %s, code: %d, host: %s)", req.Method, req.URL.String(), rule.Name, resp.StatusCode, req.Host))

	// Ensure the response is JSON before attempting to parse/modify it
	contentType := resp.Header.Get("Content-Type")
	isJSONResponse := strings.Contains(strings.ToLower(contentType), "application/json")

	switch rule.Action {
	case "log":
		if len(body) > 0 {
			// For large bodies, log only a preview
			logPreview := string(body)
			if len(logPreview) > 500 {
				logPreview = logPreview[:500] + "... (truncated)"
			}
			addLog(fmt.Sprintf("📝 HTTP RESPONSE body (log): %s", logPreview))
		} else {
			addLog("📝 HTTP RESPONSE body (log): [EMPTY]")
		}
		return body, false

	case "modify":
		if !isJSONResponse {
			addLog(fmt.Sprintf("⚠️ 'modify' action for HTTP RESPONSE %s %s, but response is not JSON (Content-Type: %s). No modification.", req.Method, req.URL.Path, contentType))
			return body, false
		}
		// Example: Modify alternateTitles for Sonarr
		if strings.Contains(strings.ToLower(req.URL.Path), "/api/v3/series") && strings.EqualFold(req.Method, "GET") {
			// Your /api/v3/series modification logic (the one you had)
			// ... (omitted for brevity, but it would go here) ...
			// For example, assume it's in a separate function:
			modifiedData, wasActuallyModified := yourExistingSeriesModificationLogic(body)
			if wasActuallyModified {
				addLog("🔄 HTTP RESPONSE body /api/v3/series modified.")
				return modifiedData, true
			}
		}
		addLog(fmt.Sprintf("ℹ️ 'modify' action for HTTP RESPONSE %s %s, but no specific modification applied.", req.Method, req.URL.Path))

	case "block": // Blocking a response generally doesn't make sense, unless replacing it with an error.
		addLog(fmt.Sprintf("🚫 'block' action on HTTP RESPONSE not implemented (usually not useful). For rule '%s' on %s %s", rule.Name, req.Method, req.URL.String()))
		return body, false
	}
	return body, false
}

// You need to implement this function if you use it in modifyResponseBody
func yourExistingSeriesModificationLogic(body []byte) ([]byte, bool) {
	// Copy your modification logic for /api/v3/series responses here
	// It should parse JSON, add/modify alternateTitles, and remarshal.
	// Return the modified body and true if modifications were made, otherwise body and false.
	// Simplified example:
	var seriesData interface{} // can be []map[string]interface{} or map[string]interface{}
	if err := json.Unmarshal(body, &seriesData); err != nil {
		addLog(fmt.Sprintf("Error unmarshal in yourExistingSeriesModificationLogic: %v", err))
		return body, false
	}

	modified := false
	// ... Your logic to iterate over seriesData, find 'alternateTitles', 'title',
	// and use seriesMappings to add/modify titles ...
	// If modifications are made, set modified = true

	if modified {
		if newBody, err := json.Marshal(seriesData); err == nil {
			return newBody, true
		}
	}
	return body, false
}

// httpProxyHandler for direct HTTP requests (admin, or HTTP proxy for Sonarr)
func httpProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Serve the admin interface
	if strings.HasPrefix(r.URL.Path, "/web/") {
		// Determine the admin sub-route
		adminSubRoute := strings.TrimPrefix(r.URL.Path, "/web")
		switch adminSubRoute {
		case "/admin":
			adminHandler(w, r)
		case "/add-mapping":
			addMappingHandler(w, r)
		case "/delete-mapping":
			deleteMappingHandler(w, r)
		case "/test-search":
			testSearchHandler(w, r)
		case "/logs":
			logsHandler(w, r)
		case "/clear-logs":
			clearLogsHandler(w, r)
		case "/rules":
			rulesHandler(w, r)
		case "/add-rule":
			addRuleHandler(w, r)
		case "/delete-rule":
			deleteRuleHandler(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}
	// Redirect from root to admin
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/web/admin", http.StatusTemporaryRedirect)
		return
	}

	// If not for admin, it's a request to proxy to Sonarr
	targetURL := url.URL{
		Scheme:   "http", // Sonarr is assumed to be HTTP locally
		Host:     SONARR_HOST,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	addLog(fmt.Sprintf("🌐 HTTP request to proxy: %s %s -> %s", r.Method, r.URL.String(), targetURL.String()))

	// Read the original request body
	var requestBodyBytes []byte
	var err error
	if r.Body != nil && r.Body != http.NoBody {
		requestBodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			addLog(fmt.Sprintf("❌ Error reading HTTP request body: %v", err))
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		r.Body.Close() // Important to close the original body
	}

	// Modify request body if necessary
	modifiedRequestBodyBytes, wasReqBodyModified := modifyRequestBody(requestBodyBytes, r)

	// Create the new request to the target
	var bodyReader io.Reader
	if len(modifiedRequestBodyBytes) > 0 {
		bodyReader = bytes.NewReader(modifiedRequestBodyBytes)
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), bodyReader)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error creating proxy request: %v", err))
		http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers from original request to proxy request
	// (except proxy-specific or hop-by-hop connection headers)
	for name, values := range r.Header {
		// Filter hop-by-hop headers
		if name == "Proxy-Connection" || name == "Proxy-Authenticate" || name == "Proxy-Authorization" ||
			name == "Connection" || name == "Keep-Alive" || name == "Transfer-Encoding" || name == "Upgrade" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}
	// Ensure Host header is correct for the target
	proxyReq.Host = targetURL.Host
	if wasReqBodyModified || (len(requestBodyBytes) > 0 && len(modifiedRequestBodyBytes) == 0) { // If modified or emptied
		proxyReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedRequestBodyBytes)))
	} else if len(requestBodyBytes) > 0 { // If not modified but had a body
		proxyReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(requestBodyBytes)))
	}

	// Execute the proxy request
	client := &http.Client{
		// Avoid following redirects automatically for a more transparent proxy
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second, // Timeout for the request to Sonarr
	}
	resp, err := client.Do(proxyReq)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error executing proxy request to %s: %v", targetURL.String(), err))
		http.Error(w, "Error communicating with target server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the response body from the target server
	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		addLog(fmt.Sprintf("❌ Error reading response from target server %s: %v", targetURL.String(), err))
		// Don't return an error to the client here, as we already have response headers
		// We could copy what we've read so far.
		// For now, continue with a potentially partial body.
	}

	// Modify response body if necessary
	modifiedResponseBodyBytes, _ := modifyResponseBody(responseBodyBytes, resp)

	// Copy headers from target server response to our client response
	// (except hop-by-hop headers)
	for name, values := range resp.Header {
		// Filter hop-by-hop headers
		if name == "Connection" || name == "Keep-Alive" || name == "Transfer-Encoding" || name == "Upgrade" ||
			name == "Proxy-Authenticate" || name == "Proxy-Authorization" || name == "Trailer" || name == "Set-Cookie" { // Set-Cookie is special, handled differently
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	// Handle Set-Cookie specifically to ensure they are passed correctly
	if cookies := resp.Cookies(); len(cookies) > 0 {
		for _, cookie := range cookies {
			http.SetCookie(w, cookie)
		}
	}

	// Update Content-Length if the body was modified
	// Or if it was emptied by modification
	if len(modifiedResponseBodyBytes) != len(responseBodyBytes) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedResponseBodyBytes)))
	}

	// Write the response status
	w.WriteHeader(resp.StatusCode)

	// Write the response body (modified or original)
	if len(modifiedResponseBodyBytes) > 0 {
		_, err = w.Write(modifiedResponseBodyBytes)
		if err != nil {
			addLog(fmt.Sprintf("❌ Error writing modified response body to client: %v", err))
		}
	}
	addLog(fmt.Sprintf("✅ HTTP request proxied: %s -> %s, Status: %d", r.URL.String(), targetURL.String(), resp.StatusCode))
}

// --- Admin Interface Handlers ---
// (adminHandler, addMappingHandler, deleteMappingHandler, testSearchHandler, logsHandler, clearLogsHandler, rulesHandler, addRuleHandler, deleteRuleHandler)
// Ensure they are complete and correct.
// Admin interface handler
func adminHandler(w http.ResponseWriter, r *http.Request) {
	mappingsMutex.RLock()
	currentMappings := make(map[string]SeriesMapping)
	for k, v := range seriesMappings { // Copy to avoid race if modified during template exec
		currentMappings[k] = v
	}
	mappingsMutex.RUnlock()

	rulesMutex.RLock()
	currentRules := make(map[string]InterceptionRule)
	for k, v := range interceptionRules {
		currentRules[k] = v
	}
	rulesMutex.RUnlock()

	var adminTemplateContent string
	if data, err := adminTemplate.ReadFile("index.html"); err == nil {
		adminTemplateContent = string(data)
	} else {
		addLog(fmt.Sprintf("Error reading template index.html: %v", err))
		http.Error(w, "Error reading template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("admin").Parse(adminTemplateContent)
	if err != nil {
		addLog(fmt.Sprintf("Error parsing admin template: %v", err))
		http.Error(w, "Error template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		SonarrHost      string
		ProxyPort       string
		MappingCount    int
		Mappings        map[string]SeriesMapping
		RulesCount      int
		Rules           map[string]InterceptionRule
		LastCacheUpdate string
		CacheStatus     string
	}{
		SonarrHost:   SONARR_HOST, // For display
		ProxyPort:    strings.TrimPrefix(PROXY_PORT, ":"),
		MappingCount: len(currentMappings),
		Mappings:     currentMappings,
		RulesCount:   len(currentRules),
		Rules:        currentRules,
	}

	sceneMappingCacheMutex.RLock()
	if !lastCacheUpdateTime.IsZero() {
		data.LastCacheUpdate = lastCacheUpdateTime.Format("2006-01-02 15:04:05 MST")
		if time.Since(lastCacheUpdateTime) > SCENEMAPPING_CACHE_DURATION+5*time.Minute {
			data.CacheStatus = "OUTDATED"
		} else if len(sceneMappingCache) > 0 {
			data.CacheStatus = "ACTIVE"
		} else {
			data.CacheStatus = "EMPTY (Update error?)"
		}
	} else {
		data.LastCacheUpdate = "Never updated"
		data.CacheStatus = "INACTIVE"
	}
	sceneMappingCacheMutex.RUnlock()

	err = tmpl.Execute(w, data)
	if err != nil {
		addLog(fmt.Sprintf("Error executing admin template: %v", err))
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Handler to add a mapping
func addMappingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var mapping SeriesMapping
	if err := json.NewDecoder(r.Body).Decode(&mapping); err != nil {
		addLog(fmt.Sprintf("Error decoding JSON for addMapping: %v", err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if mapping.Official == "" || mapping.Tracker == "" || mapping.TvdbId == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "Fields 'official', 'tracker', and 'tvdbId' are required",
		})
		return
	}

	mappingsMutex.Lock()
	key := strings.ToLower(strings.ReplaceAll(mapping.Official, " ", "_"))
	seriesMappings[key] = mapping
	mappingsMutex.Unlock()

	saveMappings() // Save after modification
	addLog(fmt.Sprintf("➕ New mapping added: '%s' (TVDB: %d) -> '%s'", mapping.Official, mapping.TvdbId, mapping.Tracker))

	// Trigger a cache update because mappings have changed
	go updateSceneMappingCache()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Mapping added successfully. Cache refreshing.",
	})
}

// Handler to delete a mapping
func deleteMappingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		addLog(fmt.Sprintf("Error decoding JSON for deleteMapping: %v", err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	mappingsMutex.Lock()
	mapping, exists := seriesMappings[reqData.Key]
	if exists {
		delete(seriesMappings, reqData.Key)
	}
	mappingsMutex.Unlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "Mapping not found",
		})
		return
	}

	saveMappings() // Save after modification
	addLog(fmt.Sprintf("🗑️ Mapping deleted: '%s' (TVDB: %d) -> '%s'", mapping.Official, mapping.TvdbId, mapping.Tracker))

	// Trigger a cache update because mappings have changed
	go updateSceneMappingCache()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Mapping deleted successfully. Cache refreshing.",
	})
}

// Handler to test a search term
func testSearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Term string `json:"term"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		addLog(fmt.Sprintf("Error decoding JSON for testSearch: %v", err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	original := reqData.Term
	modified := replaceSerieName(original) // Ensure replaceSerieName is thread-safe
	mapped := original != modified

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"original": original,
		"modified": modified,
		"mapped":   mapped,
	})
}

// Handler to clear logs
func clearLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // Use POST for an action that modifies server state
		http.Error(w, "Method not allowed, use POST.", http.StatusMethodNotAllowed)
		return
	}
	logMutex.Lock()
	logBuffer = make([]string, 0)
	logMutex.Unlock()
	addLog("📝 Logs cleared via admin interface.")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Logs cleared"})
}

// Handler for logs
func logsHandler(w http.ResponseWriter, r *http.Request) {
	logMutex.RLock()
	// Copy the buffer to avoid holding the lock during HTTP writing
	currentLogs := make([]string, len(logBuffer))
	copy(currentLogs, logBuffer)
	logMutex.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Display logs from newest to oldest
	for i := len(currentLogs) - 1; i >= 0; i-- {
		// Escape HTML to prevent XSS if logs contain HTML
		// For now, assume logs are safe or for local use.
		// For a public version, use template.HTMLEscapeString(currentLogs[i])
		fmt.Fprintf(w, "<div>%s</div>\n", currentLogs[i])
	}
}

// Handler to list interception rules
func rulesHandler(w http.ResponseWriter, r *http.Request) {
	rulesMutex.RLock()
	currentRules := make(map[string]InterceptionRule)
	for k, v := range interceptionRules { // Copy to avoid race
		currentRules[k] = v
	}
	rulesMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": currentRules,
	})
}

// Handler to add an interception rule
func addRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rule InterceptionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		addLog(fmt.Sprintf("Error decoding JSON for addRule: %v", err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if rule.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "Rule name is required",
		})
		return
	}

	rulesMutex.Lock()
	key := strings.ToLower(strings.ReplaceAll(rule.Name, " ", "_"))
	interceptionRules[key] = rule
	rulesMutex.Unlock()

	saveRules() // Save after modification
	addLog(fmt.Sprintf("➕ New interception rule added: '%s'", rule.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Rule added successfully",
	})
}

// Handler to delete an interception rule
func deleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		addLog(fmt.Sprintf("Error decoding JSON for deleteRule: %v", err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	rulesMutex.Lock()
	rule, exists := interceptionRules[reqData.Key]
	if exists {
		delete(interceptionRules, reqData.Key)
	}
	rulesMutex.Unlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "Rule not found",
		})
		return
	}

	saveRules() // Save after modification
	addLog(fmt.Sprintf("🗑️ Interception rule deleted: '%s'", rule.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Rule deleted successfully",
	})
}

// --- End of Admin Handlers ---

func main() {
	// Configure standard logger
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds) // No need for Lshortfile if addLog handles it

	// Load mappings and rules
	loadMitmCertificate()
	loadMappings()
	loadRules()

	// Add default mappings if none are loaded
	if len(seriesMappings) == 0 {
		addLog("No mappings found, adding default mappings.")
		mappingsMutex.Lock()
		seriesMappings["the_mandalorian_default"] = SeriesMapping{
			TvdbId: 361753, Official: "The Mandalorian", Tracker: "The.Mandalorian", Season: -1, Note: "Default example",
		}
		seriesMappings["what_we_do_in_the_shadows_default"] = SeriesMapping{
			TvdbId: 355218, Official: "What We Do in the Shadows", Tracker: "What.We.Do.in.the.Shadows.Series", Season: -1, Note: "Default example with suffix",
		}
		mappingsMutex.Unlock()
		saveMappings()
	}

	// Start goroutine to refresh scenemapping cache
	go func() {
		// Wait a bit for everything to initialize and not to overload at startup
		time.Sleep(10 * time.Second)
		updateSceneMappingCache() // First update
		ticker := time.NewTicker(SCENEMAPPING_CACHE_DURATION)
		defer ticker.Stop()
		for {
			// Using a select would allow for clean shutdown of the goroutine if needed
			// For now, a simple loop suffices.
			<-ticker.C
			updateSceneMappingCache()
		}
	}()

	addLog(fmt.Sprintf("🚀 Sonarr Proxy (with scenemapping cache) started on port %s", PROXY_PORT))
	addLog(fmt.Sprintf("🎯 Direct HTTP proxying (for admin and Sonarr if configured) to: %s", SONARR_HOST))
	addLog("📡 Intercepting CONNECT for services.sonarr.tv to serve scenemapping from cache.")
	addLog(fmt.Sprintf("⚙️ Admin interface available at: http://localhost%s/web/admin", PROXY_PORT))
	addLog(fmt.Sprintf("📋 %d mappings loaded.", len(seriesMappings)))
	addLog(fmt.Sprintf("📏 %d interception rules loaded.", len(interceptionRules)))

	// Define the main server handler
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connectHandler(w, r)
		} else {
			httpProxyHandler(w, r)
		}
	})

	server := &http.Server{
		Addr:    PROXY_PORT,
		Handler: mainHandler,
		// ... other server configurations ...
	}

	addLog(fmt.Sprintf("HTTP Server listening on %s", PROXY_PORT))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("❌ HTTP Server startup error: %v", err)
	}
	addLog("🏁 Server stopped.") // This log might appear twice if the first one is for a different shutdown path.
}
