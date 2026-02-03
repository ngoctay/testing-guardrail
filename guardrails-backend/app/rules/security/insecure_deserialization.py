"""Insecure deserialization detection rule.

Detects potentially unsafe deserialization of untrusted data that could
lead to remote code execution or other security vulnerabilities.
"""

import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class InsecureDeserializationRule(BaseRule):
    """Detect potential insecure deserialization vulnerabilities."""

    rule_id = "SEC-005"
    name = "Insecure Deserialization Detection"
    description = "Detects potentially unsafe deserialization of untrusted data"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "php", "ruby", "csharp"]
    owasp_mapping = "A08:2021 - Software and Data Integrity Failures"
    cwe_id = "CWE-502"
    references = [
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ]

    # Dangerous deserialization patterns by language
    DANGEROUS_PATTERNS = {
        'python': [
            (r'pickle\.loads?\s*\(', 'pickle.load/loads - can execute arbitrary code'),
            (r'cPickle\.loads?\s*\(', 'cPickle.load/loads - can execute arbitrary code'),
            (r'_pickle\.loads?\s*\(', '_pickle.load/loads - can execute arbitrary code'),
            (r'shelve\.open\s*\(', 'shelve.open - uses pickle internally'),
            (r'marshal\.loads?\s*\(', 'marshal.load/loads - unsafe for untrusted data'),
            (r'yaml\.load\s*\([^)]*\)', 'yaml.load without safe_load - can execute code'),
            (r'yaml\.unsafe_load\s*\(', 'yaml.unsafe_load - explicitly unsafe'),
            (r'jsonpickle\.decode\s*\(', 'jsonpickle.decode - can execute arbitrary code'),
            (r'dill\.loads?\s*\(', 'dill.load/loads - can execute arbitrary code'),
            (r'cloudpickle\.loads?\s*\(', 'cloudpickle - can execute arbitrary code'),
        ],
        'javascript': [
            (r'eval\s*\(\s*JSON\.parse', 'eval with JSON.parse - code execution risk'),
            (r'new\s+Function\s*\([^)]*JSON', 'Function constructor with JSON - code execution'),
            (r'serialize-javascript.*\{\s*unsafe', 'serialize-javascript with unsafe option'),
            (r'node-serialize', 'node-serialize - known RCE vulnerability'),
            (r'funcster', 'funcster - deserializes functions'),
        ],
        'typescript': [
            (r'eval\s*\(\s*JSON\.parse', 'eval with JSON.parse - code execution risk'),
            (r'new\s+Function\s*\([^)]*JSON', 'Function constructor with JSON - code execution'),
            (r'node-serialize', 'node-serialize - known RCE vulnerability'),
        ],
        'java': [
            (r'ObjectInputStream\s*\(', 'ObjectInputStream - Java deserialization vulnerability'),
            (r'XMLDecoder\s*\(', 'XMLDecoder - can execute arbitrary code'),
            (r'XStream\s*\(\s*\)\.fromXML', 'XStream.fromXML - deserialization risk'),
            (r'readObject\s*\(\s*\)', 'readObject() - potential gadget chain'),
            (r'ObjectMapper.*enableDefaultTyping', 'Jackson enableDefaultTyping - polymorphic deserialization'),
            (r'@JsonTypeInfo.*Id\.CLASS', 'Jackson JsonTypeInfo with CLASS - deserialization risk'),
            (r'SerializationUtils\.deserialize', 'Apache Commons SerializationUtils - unsafe'),
            (r'Yaml\s*\(\s*\)\.load', 'SnakeYAML load - can instantiate arbitrary classes'),
        ],
        'php': [
            (r'unserialize\s*\(', 'unserialize() - PHP object injection vulnerability'),
            (r'maybe_unserialize\s*\(', 'maybe_unserialize() - WordPress deserialization'),
        ],
        'ruby': [
            (r'Marshal\.load\s*\(', 'Marshal.load - can execute arbitrary code'),
            (r'YAML\.load\s*\(', 'YAML.load - can instantiate arbitrary objects'),
            (r'Psych\.load\s*\(', 'Psych.load - unsafe YAML loading'),
            (r'Oj\.load\s*\([^)]*mode:\s*:object', 'Oj.load with object mode - unsafe'),
        ],
        'csharp': [
            (r'BinaryFormatter\s*\(\s*\)\.Deserialize', 'BinaryFormatter.Deserialize - unsafe'),
            (r'NetDataContractSerializer.*Deserialize', 'NetDataContractSerializer - unsafe'),
            (r'ObjectStateFormatter.*Deserialize', 'ObjectStateFormatter - unsafe'),
            (r'SoapFormatter.*Deserialize', 'SoapFormatter - unsafe'),
            (r'LosFormatter.*Deserialize', 'LosFormatter - unsafe'),
            (r'JsonConvert\.DeserializeObject.*TypeNameHandling', 'Json.NET TypeNameHandling - risk'),
            (r'JavaScriptSerializer\s*\(\s*\)\.Deserialize', 'JavaScriptSerializer - type confusion'),
        ],
    }

    # Patterns that indicate safe usage
    SAFE_PATTERNS = {
        'python': [
            r'yaml\.safe_load',
            r'yaml\.SafeLoader',
            r'Loader\s*=\s*yaml\.SafeLoader',
        ],
        'java': [
            r'ObjectInputFilter',
            r'setObjectInputFilter',
            r'lookAheadObjectInputStream',
        ],
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        patterns = self.DANGEROUS_PATTERNS.get(lang_lower, [])
        safe_patterns = self.SAFE_PATTERNS.get(lang_lower, [])

        for pattern, description in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                line_start = code[:match.start()].count('\n') + 1
                line_end = code[:match.end()].count('\n') + 1

                # Get context around the match
                start_line = max(0, line_start - 3)
                end_line = min(len(lines), line_end + 3)
                context = '\n'.join(lines[start_line:end_line])

                # Check if safe patterns are used
                is_safe = any(
                    re.search(safe_pattern, context, re.IGNORECASE)
                    for safe_pattern in safe_patterns
                )

                if is_safe:
                    continue

                # Special case: check if yaml.load has Loader=SafeLoader
                if 'yaml.load' in pattern.lower():
                    line_content = lines[line_start - 1] if line_start <= len(lines) else ""
                    if 'SafeLoader' in line_content or 'safe_load' in line_content:
                        continue

                code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    title="Insecure Deserialization Vulnerability",
                    description=f"Detected {description}. Deserializing untrusted data can lead to "
                               "remote code execution, denial of service, or other attacks.",
                    explanation="Insecure deserialization occurs when untrusted data is used to abuse "
                               "the logic of an application, inflict denial of service attacks, or "
                               "execute arbitrary code. Many deserialization libraries allow the "
                               "creation of arbitrary objects, which attackers can exploit to run "
                               "malicious code during the deserialization process.",
                    suggested_fix=self._get_fix_suggestion(lang_lower, description),
                ))

        return results

    def _get_fix_suggestion(self, language: str, issue_type: str) -> str:
        """Get language-specific fix suggestion."""
        fixes = {
            'python': '''# Safe alternatives for Python deserialization

# Instead of pickle (NEVER use with untrusted data):
# BAD: data = pickle.loads(untrusted_input)

# Use JSON for simple data structures:
import json
data = json.loads(untrusted_input)

# For YAML, always use safe_load:
import yaml
data = yaml.safe_load(untrusted_input)
# Or explicitly specify SafeLoader:
data = yaml.load(untrusted_input, Loader=yaml.SafeLoader)

# If you must use pickle, validate/sign the data:
import hmac
import hashlib

def secure_loads(data: bytes, secret_key: bytes):
    # Verify HMAC before deserializing
    received_mac = data[:32]
    payload = data[32:]
    expected_mac = hmac.new(secret_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("Invalid signature")
    return pickle.loads(payload)  # Only from trusted, signed source''',

            'javascript': '''// Safe alternatives for JavaScript/Node.js

// Use JSON.parse for JSON data (safe for data, not code):
const data = JSON.parse(untrustedInput);

// NEVER use eval() or new Function() with untrusted data
// BAD: eval(JSON.parse(input))
// BAD: new Function('return ' + input)()

// For complex objects, use a schema validator:
import Ajv from 'ajv';
const ajv = new Ajv();
const validate = ajv.compile(schema);
const data = JSON.parse(untrustedInput);
if (!validate(data)) {
  throw new Error('Invalid data format');
}

// Avoid node-serialize - it has known RCE vulnerabilities
// Use JSON or a safe serialization library instead''',

            'typescript': '''// Safe alternatives for TypeScript/Node.js

// Use JSON.parse with type validation:
interface SafeData {
  name: string;
  value: number;
}

function parseData(input: string): SafeData {
  const parsed = JSON.parse(input);
  // Validate the structure
  if (typeof parsed.name !== 'string' || typeof parsed.value !== 'number') {
    throw new Error('Invalid data structure');
  }
  return parsed as SafeData;
}

// Use zod or io-ts for runtime type validation:
import { z } from 'zod';

const DataSchema = z.object({
  name: z.string(),
  value: z.number(),
});

const data = DataSchema.parse(JSON.parse(untrustedInput));''',

            'java': '''// Safe alternatives for Java deserialization

// 1. Use JSON instead of Java serialization:
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
// Disable default typing (polymorphic deserialization)
mapper.deactivateDefaultTyping();
MyClass obj = mapper.readValue(jsonString, MyClass.class);

// 2. If you must use ObjectInputStream, add a filter:
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null) {
        // Only allow specific classes
        if (clazz.getName().startsWith("com.myapp.")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});

// 3. For YAML, use SafeConstructor:
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

Yaml yaml = new Yaml(new SafeConstructor());
Map<String, Object> data = yaml.load(input);''',

            'php': '''// Safe alternatives for PHP

// NEVER use unserialize() on untrusted data
// BAD: $data = unserialize($userInput);

// Use JSON instead:
$data = json_decode($userInput, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    throw new Exception('Invalid JSON');
}

// If you must use unserialize, restrict allowed classes (PHP 7+):
$data = unserialize($input, [
    'allowed_classes' => ['SafeClass1', 'SafeClass2']
]);

// Or disallow all classes:
$data = unserialize($input, ['allowed_classes' => false]);''',

            'ruby': '''# Safe alternatives for Ruby deserialization

# Instead of Marshal.load (NEVER use with untrusted data):
# BAD: data = Marshal.load(untrusted_input)

# Use JSON for data:
require 'json'
data = JSON.parse(untrusted_input)

# For YAML, use safe_load (Ruby 2.5+):
require 'yaml'
data = YAML.safe_load(untrusted_input)

# Or specify permitted classes explicitly:
data = YAML.safe_load(
  untrusted_input,
  permitted_classes: [Date, Time],
  permitted_symbols: [],
  aliases: false
)''',

            'csharp': '''// Safe alternatives for C# deserialization

// NEVER use BinaryFormatter, NetDataContractSerializer, etc.
// BAD: var formatter = new BinaryFormatter();
// BAD: var obj = formatter.Deserialize(stream);

// Use System.Text.Json (safe by default):
using System.Text.Json;

var options = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
};
var obj = JsonSerializer.Deserialize<MyClass>(jsonString, options);

// If using Newtonsoft.Json, avoid TypeNameHandling:
using Newtonsoft.Json;

var settings = new JsonSerializerSettings
{
    // NEVER use TypeNameHandling.All or TypeNameHandling.Auto
    TypeNameHandling = TypeNameHandling.None
};
var obj = JsonConvert.DeserializeObject<MyClass>(json, settings);

// For XML, use XmlSerializer (not XmlDecoder):
using System.Xml.Serialization;
var serializer = new XmlSerializer(typeof(MyClass));
var obj = (MyClass)serializer.Deserialize(reader);''',
        }

        return fixes.get(language, '''Avoid deserializing untrusted data. Use safe alternatives:
1. Use JSON for data interchange (not code execution)
2. If serialization is needed, use a safe library with schema validation
3. Never deserialize data from untrusted sources without validation
4. Consider using digital signatures to verify data integrity''')
