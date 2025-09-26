# CVE-2023-45612 Reproduction Steps

### Prerequisites
- **Java 11 or later**
- **Gradle 7.0+**
- **Python 3.6+** (for POC script)

### Steps

```
git clone git@github.com:bbugdigger/ktor-xxe-poc.git
cd ktor-xxe-poc
.\gradlew build
.\gradlew run
```

In new tab with same folder destination run PoC script
```
python .\xxe_poc.py
```
