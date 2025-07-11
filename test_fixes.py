import subprocess
import sys
import os

# Change to project directory
os.chdir(r"C:\Users\ckoch\OneDrive\Documents\GitHub\fda-sbom-generator")

# Test the Java scanner fix
print("Testing Java Maven scanner...")
result = subprocess.run([
    sys.executable, "-m", "pytest", 
    "tests/unit/test_scanners.py::TestJavaScanner::test_parse_maven_pom", 
    "-v", "-s"
], capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")

if result.returncode == 0:
    print("✅ Java scanner test PASSED!")
else:
    print("❌ Java scanner test still failing")
