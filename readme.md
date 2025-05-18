# 🎬 Sonarr MitM & Scene Mapping Proxy

This Go application acts as an HTTP/HTTPS proxy designed to intercept and modify specific Sonarr traffic. Its primary features include:

1. **Scene Mapping Augmentation**: Intercepts requests to `services.sonarr.tv/v1/scenemapping`, injects custom series mappings defined by the user, and serves the modified list from a local cache. This helps Sonarr correctly identify releases that use alternative naming conventions.
2. **Request/Response Modification (Rule-Based)**: Allows defining custom rules to intercept, log, modify, or block HTTP requests and responses to Sonarr's API (e.g., modifying search terms, adding alternate titles to series).
3. **Admin Web Interface**: Provides a user-friendly web UI to:
   - Manage custom series mappings.
   - Manage interception rules.
   - View real-time proxy logs.
   - Test search term transformations.

## ✨ Features

- **Local Scene Mapping Cache**: Fetches official scene mappings, adds your custom ones, and serves the combined list to Sonarr.
- **Man-in-the-Middle (MitM) for `services.sonarr.tv`**: Specifically intercepts TLS traffic for `services.sonarr.tv` to serve modified scene mappings. Requires a custom CA to be trusted by the machine running Sonarr.
- **Rule-Based Interception Engine**:
  - Match requests by HTTP method and URL pattern.
  - Intercept request or response bodies.
  - Actions: Log, Modify (with examples for Sonarr search and series API), Block.
- **Web-Based Admin UI**:
  - Add/delete series mappings (TVDB ID, official name, tracker name, season, note).
  - Add/delete interception rules (name, method, pattern, body type, action, enabled).
  - Live log viewer with clear & refresh.
  - Search term tester.
- **Configurable**: Mappings and rules are saved to JSON files (`series_mappings.json`, `interception_rules.json`).
- **Embedded HTML Template**: Admin UI is served from an embedded `index.html`.

## 🛠️ Setup and Installation

### Prerequisites

- Go (version 1.18 or newer recommended).
- OpenSSL (for generating SSL certificates).
- Sonarr instance that you want to proxy.

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd <repository-name>
```

### 2. Generate SSL Certificates for MitM

This proxy needs to perform a Man-in-the-Middle interception for `https://services.sonarr.tv` to modify scene mappings. This requires generating a local Certificate Authority (CA) and a server certificate for `services.sonarr.tv` signed by your local CA.


#### a. Create your Local Certificate Authority (CA)

You only need to do this once. Keep `mylocalca.key` very secure!

**i. Generate the CA private key** (you will be prompted for a passphrase):

```bash
openssl genrsa -aes256 -out mylocalca.key 4096
```

**ii. Generate the CA root certificate** (valid for 10 years):

```bash
openssl req -new -x509 -sha256 -days 3650 -key mylocalca.key -out mylocalca.crt
```

You will be prompted for the CA key's passphrase and then for details for the certificate (Country, Organization, etc.). For Common Name (CN), you can enter something like `My Sonarr Proxy Local CA`.

#### b. Create the Server Certificate for services.sonarr.tv

**i. Generate a private key for services.sonarr.tv** (unencrypted):

```bash
openssl genrsa -out services.sonarr.tv.key 2048
```

**ii. Create a configuration file for Subject Alternative Names (SANs)**. Create a file named `services.sonarr.tv.ext` with the following content:

```ini
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = services.sonarr.tv
```

**iii. Create a Certificate Signing Request (CSR):**

```bash
openssl req -new -sha256 -key services.sonarr.tv.key -out services.sonarr.tv.csr
```

When prompted for the Common Name (CN), you **MUST** enter `services.sonarr.tv`. Other fields can be filled or left default.

**iv. Sign the CSR with your local CA:**

```bash
openssl x509 -req -sha256 -in services.sonarr.tv.csr \
  -CA mylocalca.crt -CAkey mylocalca.key -CAcreateserial \
  -out services.sonarr.tv.crt \
  -days 398 \
  -extfile services.sonarr.tv.ext
```

You will be prompted for the passphrase of `mylocalca.key`. This creates `services.sonarr.tv.crt` and `mylocalca.srl` (serial number file).

#### c. Place Certificates

Place `services.sonarr.tv.crt` and `services.sonarr.tv.key` in the same directory where you will run the Go proxy application.

### 3. Trust Your Local CA (mylocalca.crt)

This is a **CRUCIAL** step. The machine running Sonarr must trust your `mylocalca.crt` file. Otherwise, Sonarr will reject the certificate presented by the proxy.

#### Windows:

1. Open `mmc.exe`.
2. **File** > **Add/Remove Snap-in...**
3. Select "Certificates", click **Add**.
4. Choose "Computer account", click **Next**, then **Finish**, then **OK**.
5. In the console tree, expand **Certificates (Local Computer)** > **Trusted Root Certification Authorities** > **Certificates**.
6. Right-click "Certificates", select **All Tasks** > **Import...**
7. Browse to and select `mylocalca.crt`.
8. Place in the "Trusted Root Certification Authorities" store.
9. Complete the wizard.

#### Linux (Debian/Ubuntu based):

```bash
sudo cp mylocalca.crt /usr/local/share/ca-certificates/mylocalca.crt
sudo update-ca-certificates
```

#### Linux (Fedora/RHEL based):

```bash
sudo cp mylocalca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract
```

#### macOS:

1. Double-click `mylocalca.crt`.
2. Keychain Access will open. Add the certificate to the "System" keychain.
3. Find the certificate in the System keychain, double-click it.
4. Expand the "Trust" section.
5. Set "When using this certificate:" to **Always Trust**.
6. Close the window (you may need to enter your admin password).

#### Docker:

If Sonarr is running in Docker, the CA certificate must be installed inside the Sonarr container. This process varies depending on the base image of the Sonarr container. You'll typically need to copy the `.crt` file into the container and run the appropriate system command to update CA certificates (e.g., `update-ca-certificates` for Debian-based images). This might involve creating a custom Dockerfile.

> **Note**: After installing the CA, you might need to restart Sonarr.

### 4. Build and Run the Proxy

**i. Build the application:**

```bash
go build .
```

**ii. Run the application:**

```bash
./<executable-name> # (e.g., ./sonarr-proxy if your module name is sonarr-proxy)
```

The proxy will start, typically on port `:8990`. Check the startup logs for the exact address of the admin UI.

### 5. Configure Sonarr to Use the Proxy

1. Open Sonarr's web interface.
2. Go to **Settings** > **General**.
3. Under the "Proxy" section:
   - **Enable Proxy**: Yes
   - **Proxy Type**: HTTP
   - **Hostname**: `localhost` (or the IP address of the machine running your Go proxy if Sonarr is on a different machine/container but can reach it)
   - **Port**: `8990` (or whatever `PROXY_PORT` is set to in the Go app).
   - (Username/Password fields can be left blank unless your proxy implements authentication, which this one currently does not).
4. Click "Save changes".
5. It's a good idea to test the proxy settings within Sonarr if it has a "Test" button for the proxy.
6. Restart Sonarr if changes don't seem to take effect immediately, especially regarding SSL connections.

Sonarr will now route its HTTP and HTTPS (via CONNECT requests) traffic through your Go proxy.

## 🖥️ Using the Admin Interface

Access the admin interface by navigating to `http://localhost:8990/web/admin` (or the appropriate port) in your web browser.

- **Mapping Management**: Add, view, and delete custom series mappings. These are used to augment the scene mappings fetched from `services.sonarr.tv`.
- **Interception Rules**: Define rules to modify Sonarr's API requests/responses.
- **Real-time Logs**: View logs from the proxy.
- **Search Test**: Test how a search term would be transformed by your defined mappings.

## ⚙️ Configuration Files

- `series_mappings.json`: Stores your custom series mappings.
- `interception_rules.json`: Stores your custom interception rules.

These files are created/updated automatically by the application.

## ⚠️ Security Note

- The MitM functionality relies on your local CA being trusted. Keep your `mylocalca.key` (CA private key) extremely secure.
- This proxy is intended for local/trusted network use. It does not implement robust authentication or advanced security measures for public exposure.

## 📄 License

This project is licensed under the MIT License.

Copyright (c) 2025 TOomaAh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.