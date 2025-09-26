# Developer Guidelines: Preventing XXE Vulnerabilities
## Comprehensive Security Guidelines for XML Processing in Ktor Applications

---

## Table of Contents

1. [Understanding XXE Vulnerabilities](#understanding-xxe-vulnerabilities)
2. [Immediate Actions](#immediate-actions)
3. [Secure XML Configuration](#secure-xml-configuration)
4. [Input Validation](#input-validation)
5. [Security Best Practices](#security-best-practices)
6. [Testing and Monitoring](#testing-and-monitoring)
7. [Code Review Checklist](#code-review-checklist)

---

## Understanding XXE Vulnerabilities

### What is XXE?
XML External Entity (XXE) attacks exploit vulnerabilities in XML parsers that process external entity references. Attackers can use these references to:

- **Read local files** from the server filesystem
- **Perform SSRF attacks** against internal services
- **Cause denial of service** through resource exhaustion
- **Execute remote code** in extreme cases

### How XXE Works in Ktor
```kotlin
// VULNERABLE: Default XML processing
install(ContentNegotiation) {
    val xmlFormat = XML() // Uses unsafe defaults in xmlutil < 0.86.2
    register(ContentType.Application.Xml, XmlConverter(xmlFormat))
}

// Attacker sends:
// <?xml version="1.0"?>
// <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
// <root>&xxe;</root>
```

---

## Immediate Actions

### 1. Update Dependencies Immediately
```kotlin
// gradle/libs.versions.toml
[versions]
ktor = "2.3.5"        # Minimum safe version
xmlutil = "0.86.2"    # Minimum safe version
```

### 2. Audit Existing Code
Search your codebase for these patterns:
```bash
# Find XML processing code
grep -r "ContentNegotiation" src/
grep -r "XML()" src/
grep -r "DocumentBuilderFactory" src/
grep -r "SAXParserFactory" src/
grep -r "XMLReader" src/
```

### 3. Emergency Mitigation
If you cannot update immediately, disable XML endpoints:
```kotlin
routing {
    post("/xml") {
        call.respond(HttpStatusCode.ServiceUnavailable, "XML processing temporarily disabled")
    }
}
```

---

## Secure XML Configuration

### 1. Ktor ContentNegotiation (Recommended)
```kotlin
import nl.adaptivity.xmlutil.serialization.*
import nl.adaptivity.xmlutil.*

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        // SECURE: Explicit safe configuration
        val secureXmlFormat = XML {
            xmlDeclMode = XmlDeclMode.Auto
            indent = 2
            repairNamespaces = true
            
            // Security: These are safe defaults in xmlutil 0.86.2+
            // but explicit configuration is recommended
            xmlVersion = XmlVersion.XML10
        }
        
        register(ContentType.Application.Xml, XmlConverter(secureXmlFormat))
        register(ContentType.Text.Xml, XmlConverter(secureXmlFormat))
    }
}
```

### 2. Manual XML Parser Configuration
```kotlin
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory

fun createSecureDocumentBuilderFactory(): DocumentBuilderFactory {
    val factory = DocumentBuilderFactory.newInstance()
    
    // CRITICAL: Disable external entity processing
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
    
    // Additional security features
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.isExpandEntityReferences = false
    factory.isNamespaceAware = true
    factory.isValidating = false
    
    return factory
}

fun createSecureSAXParserFactory(): SAXParserFactory {
    val factory = SAXParserFactory.newInstance()
    
    // CRITICAL: Disable external entity processing
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
    
    // Additional security
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.isNamespaceAware = true
    factory.isValidating = false
    
    return factory
}
```

### 3. Custom Secure XML Converter
```kotlin
import io.ktor.http.*
import io.ktor.serialization.*
import io.ktor.util.reflect.*
import io.ktor.utils.io.*
import io.ktor.utils.io.charsets.*

class SecureXmlConverter : ContentConverter {
    
    override suspend fun deserialize(charset: Charset, typeInfo: TypeInfo, content: ByteReadChannel): Any? {
        val xmlText = content.toInputStream().reader(charset).readText()
        
        // Security: Validate XML before processing
        if (containsExternalEntities(xmlText)) {
            throw SecurityException("External entities not allowed")
        }
        
        if (containsDoctypeDeclaration(xmlText)) {
            throw SecurityException("DOCTYPE declarations not allowed")
        }
        
        // Process with secure parser
        return processSecureXml(xmlText, typeInfo)
    }
    
    private fun containsExternalEntities(xml: String): Boolean {
        val upperXml = xml.uppercase()
        return upperXml.contains("<!ENTITY") && 
               (upperXml.contains("SYSTEM") || upperXml.contains("PUBLIC"))
    }
    
    private fun containsDoctypeDeclaration(xml: String): Boolean {
        return xml.uppercase().contains("<!DOCTYPE")
    }
    
    private fun processSecureXml(xmlText: String, typeInfo: TypeInfo): Any? {
        val factory = createSecureDocumentBuilderFactory()
        val builder = factory.newDocumentBuilder()
        val document = builder.parse(java.io.ByteArrayInputStream(xmlText.toByteArray()))
        
        // Custom deserialization logic here
        return deserializeFromDocument(document, typeInfo)
    }
    
    override suspend fun serialize(contentType: ContentType, charset: Charset, typeInfo: TypeInfo, value: Any): OutgoingContent {
        // Safe serialization logic
        return TextContent(value.toString(), contentType.withCharset(charset))
    }
}
```

---

## Input Validation

### 1. XML Structure Validation
```kotlin
@Serializable
data class UserData(
    val name: String,
    val email: String
) {
    init {
        // Validate field contents
        require(name.isNotBlank()) { "Name cannot be blank" }
        require(name.length <= 100) { "Name too long" }
        require(email.matches(Regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"))) { 
            "Invalid email format" 
        }
        
        // Security: Check for XML injection attempts
        require(!name.contains('<')) { "Invalid characters in name" }
        require(!email.contains('<')) { "Invalid characters in email" }
    }
}
```

### 2. Request Size Limits
```kotlin
install(DefaultHeaders) {
    // Limit request body size to prevent DoS
    header("Content-Length-Limit", "1048576") // 1MB limit
}

routing {
    post("/xml") {
        val contentLength = call.request.headers["Content-Length"]?.toLongOrNull() ?: 0
        if (contentLength > 1_048_576) { // 1MB
            call.respond(HttpStatusCode.RequestEntityTooLarge, "Request too large")
            return@post
        }
        
        // Process XML...
    }
}
```

### 3. Content Type Validation
```kotlin
post("/xml") {
    val contentType = call.request.contentType()
    if (!contentType.match(ContentType.Application.Xml) && 
        !contentType.match(ContentType.Text.Xml)) {
        call.respond(HttpStatusCode.UnsupportedMediaType, "Only XML content allowed")
        return@post
    }
    
    // Process XML...
}
```

---

## Security Best Practices

### 1. Principle of Least Privilege
```kotlin
// Only allow specific XML structures
sealed class AllowedXmlData {
    @Serializable
    data class UserRegistration(val username: String, val email: String) : AllowedXmlData()
    
    @Serializable  
    data class ProductInfo(val name: String, val price: Double) : AllowedXmlData()
}

post("/xml/user") {
    val userData = call.receive<AllowedXmlData.UserRegistration>()
    // Process only user registration data
}
```

### 2. Error Handling
```kotlin
post("/xml") {
    try {
        val userData = call.receive<UserData>()
        call.respondText("Success: ${userData.name}")
    } catch (e: SecurityException) {
        // Log security violation
        logger.warn("XML security violation from ${call.request.origin.remoteHost}: ${e.message}")
        call.respond(HttpStatusCode.BadRequest, "Invalid XML format")
    } catch (e: Exception) {
        // Don't leak internal error details
        logger.error("XML processing error", e)
        call.respond(HttpStatusCode.BadRequest, "Processing error")
    }
}
```

### 3. Network Security
```kotlin
// Restrict outbound connections if XML parser makes network calls
install(CallLogging) {
    level = Level.INFO
    filter { call -> call.request.path().startsWith("/xml") }
}

// Monitor for suspicious network activity
class NetworkSecurityInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        
        // Block suspicious domains
        val suspiciousDomains = listOf("metadata.google.internal", "169.254.169.254")
        if (suspiciousDomains.any { request.url.host.contains(it) }) {
            throw SecurityException("Blocked suspicious network request")
        }
        
        return chain.proceed(request)
    }
}
```

### 4. Rate Limiting
```kotlin
// Install rate limiting for XML endpoints
install(RateLimit) {
    register(RateLimitName("xml-processing")) {
        rateLimiter(limit = 10, refillPeriod = 60.seconds)
        requestKey { call ->
            call.request.origin.remoteHost
        }
    }
}

routing {
    rateLimit(RateLimitName("xml-processing")) {
        post("/xml") {
            // XML processing with rate limiting
        }
    }
}
```

---

## Testing and Monitoring

### 1. Security Testing
```kotlin
// Unit test for XXE protection
@Test
fun `should reject XXE payloads`() = testApplication {
    application {
        configureSerialization()
        configureRouting()
    }
    
    val xxePayload = """
        <?xml version="1.0"?>
        <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <UserData><name>&xxe;</name><email>test@test.com</email></UserData>
    """.trimIndent()
    
    client.post("/xml") {
        contentType(ContentType.Application.Xml)
        setBody(xxePayload)
    }.apply {
        assertEquals(HttpStatusCode.BadRequest, status)
        assertFalse(bodyAsText().contains("root:"))
    }
}

// Integration test
@Test
fun `should process valid XML safely`() = testApplication {
    val validXml = """
        <?xml version="1.0"?>
        <UserData><name>John</name><email>john@example.com</email></UserData>
    """.trimIndent()
    
    client.post("/xml") {
        contentType(ContentType.Application.Xml)
        setBody(validXml)
    }.apply {
        assertEquals(HttpStatusCode.OK, status)
        assertTrue(bodyAsText().contains("John"))
    }
}
```

### 2. Monitoring and Alerting
```kotlin
// Custom monitoring for XML processing
class XmlSecurityMonitor {
    private val securityViolations = Counter.build()
        .name("xml_security_violations_total")
        .help("Total XML security violations")
        .register()
    
    private val processingTime = Histogram.build()
        .name("xml_processing_duration_seconds")
        .help("XML processing duration")
        .register()
    
    fun recordSecurityViolation(violation: String, clientIp: String) {
        securityViolations.inc()
        logger.warn("XML security violation: $violation from $clientIp")
        
        // Alert if too many violations
        if (getViolationCount(clientIp) > 5) {
            alertSecurityTeam("Multiple XXE attempts from $clientIp")
        }
    }
    
    fun recordProcessingTime(duration: Duration) {
        processingTime.observe(duration.toSeconds())
        
        // Alert on unusually long processing times (potential DoS)
        if (duration.toSeconds() > 10) {
            alertSecurityTeam("Slow XML processing detected: ${duration.toSeconds()}s")
        }
    }
}
```

### 3. Automated Security Scanning
```kotlin
// Gradle task for dependency vulnerability scanning
tasks.register("securityScan") {
    doLast {
        exec {
            commandLine("./gradlew", "dependencyCheckAnalyze")
        }
    }
}

// CI/CD pipeline security check
tasks.register("xxeSecurityTest") {
    doLast {
        // Run XXE-specific security tests
        exec {
            commandLine("python", "security_tests/xxe_test.py")
        }
    }
}
```

---

## Code Review Checklist

### XML Processing Security Checklist

- [ ] **Dependencies Updated**
  - [ ] Ktor version >= 2.3.5
  - [ ] xmlutil version >= 0.86.2
  - [ ] All XML processing libraries are up-to-date

- [ ] **XML Parser Configuration**
  - [ ] External entity processing disabled
  - [ ] DOCTYPE declarations disabled (if possible)
  - [ ] Entity expansion limits set
  - [ ] Namespace awareness enabled
  - [ ] Validation disabled for untrusted input

- [ ] **Input Validation**
  - [ ] XML structure validation implemented
  - [ ] Content length limits enforced
  - [ ] Content type validation present
  - [ ] Character encoding validation
  - [ ] Malicious pattern detection

- [ ] **Error Handling**
  - [ ] Security exceptions handled properly
  - [ ] Error messages don't leak sensitive information
  - [ ] All exceptions logged for monitoring
  - [ ] Fail-safe error responses

- [ ] **Security Controls**
  - [ ] Rate limiting implemented
  - [ ] Network access restrictions in place
  - [ ] Monitoring and alerting configured
  - [ ] Security testing included

- [ ] **Code Quality**
  - [ ] No hardcoded sensitive data
  - [ ] Proper logging without sensitive data exposure
  - [ ] Thread-safe XML processing
  - [ ] Resource cleanup implemented

### Review Questions

1. **Is XML processing really necessary?** Consider JSON alternatives.
2. **Are all XML inputs from trusted sources?** If not, apply strict validation.
3. **What happens if XML processing fails?** Ensure graceful degradation.
4. **Are there any custom XML parsers?** Ensure they follow security guidelines.
5. **Is the XML processing code regularly updated?** Establish update procedures.

---

## Emergency Response Plan

### If XXE Vulnerability is Discovered

1. **Immediate Response (0-2 hours)**
   - [ ] Disable affected XML endpoints
   - [ ] Block suspicious IP addresses
   - [ ] Alert security team and management
   - [ ] Begin impact assessment

2. **Short-term Mitigation (2-24 hours)**
   - [ ] Apply emergency patches
   - [ ] Update dependencies
   - [ ] Implement input filtering
   - [ ] Monitor for exploitation attempts

3. **Long-term Resolution (1-7 days)**
   - [ ] Comprehensive security audit
   - [ ] Update all XML processing code
   - [ ] Implement enhanced monitoring
   - [ ] Update security procedures

4. **Post-Incident (1-4 weeks)**
   - [ ] Conduct lessons learned session
   - [ ] Update security training
   - [ ] Improve automated testing
   - [ ] Review and update guidelines

---

## Conclusion

XXE vulnerabilities can have severe security implications, but they are preventable with proper configuration and coding practices. The key principles are:

1. **Keep dependencies updated**
2. **Disable external entity processing**
3. **Validate all XML inputs**
4. **Implement comprehensive monitoring**
5. **Test security controls regularly**

By following these guidelines and maintaining security awareness, developers can effectively prevent XXE vulnerabilities in Ktor applications.
