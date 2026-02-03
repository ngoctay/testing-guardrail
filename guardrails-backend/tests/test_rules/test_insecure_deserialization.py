"""Tests for insecure deserialization detection rule."""

import pytest
from app.rules.security.insecure_deserialization import InsecureDeserializationRule


@pytest.fixture
def rule():
    return InsecureDeserializationRule()


class TestPythonDeserialization:
    """Test Python deserialization detection."""

    def test_detects_pickle_loads(self, rule):
        """Should detect pickle.loads usage."""
        code = """
import pickle

def load_data(data):
    return pickle.loads(data)
"""
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "pickle" in results[0].description.lower()
        assert results[0].severity.value == "critical"

    def test_detects_pickle_load(self, rule):
        """Should detect pickle.load usage."""
        code = """
import pickle

def load_from_file(f):
    return pickle.load(f)
"""
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "pickle" in results[0].description.lower()

    def test_detects_cpickle(self, rule):
        """Should detect cPickle usage."""
        code = """
import cPickle

def load_data(data):
    return cPickle.loads(data)
"""
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "cPickle" in results[0].description

    def test_detects_yaml_load(self, rule):
        """Should detect unsafe yaml.load usage."""
        code = """
import yaml

def parse_config(config_str):
    return yaml.load(config_str)
"""
        results = rule.check(code, "config.py", "python")
        assert len(results) == 1
        assert "yaml" in results[0].description.lower()

    def test_allows_yaml_safe_load(self, rule):
        """Should not flag yaml.safe_load."""
        code = """
import yaml

def parse_config(config_str):
    return yaml.safe_load(config_str)
"""
        results = rule.check(code, "config.py", "python")
        assert len(results) == 0

    def test_allows_yaml_load_with_safe_loader(self, rule):
        """Should not flag yaml.load with SafeLoader."""
        code = """
import yaml

def parse_config(config_str):
    return yaml.load(config_str, Loader=yaml.SafeLoader)
"""
        results = rule.check(code, "config.py", "python")
        assert len(results) == 0

    def test_detects_marshal_loads(self, rule):
        """Should detect marshal.loads usage."""
        code = """
import marshal

def load_data(data):
    return marshal.loads(data)
"""
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "marshal" in results[0].description.lower()

    def test_detects_jsonpickle(self, rule):
        """Should detect jsonpickle.decode usage."""
        code = """
import jsonpickle

def load_data(data):
    return jsonpickle.decode(data)
"""
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "jsonpickle" in results[0].description.lower()

    def test_detects_dill(self, rule):
        """Should detect dill.loads usage."""
        code = """
import dill

def load_model(data):
    return dill.loads(data)
"""
        results = rule.check(code, "ml.py", "python")
        assert len(results) == 1
        assert "dill" in results[0].description.lower()


class TestJavaScriptDeserialization:
    """Test JavaScript deserialization detection."""

    def test_detects_eval_json_parse(self, rule):
        """Should detect eval with JSON.parse."""
        code = """
function processData(input) {
    return eval(JSON.parse(input));
}
"""
        results = rule.check(code, "app.js", "javascript")
        assert len(results) == 1
        assert "eval" in results[0].description.lower()

    def test_detects_function_constructor_json(self, rule):
        """Should detect Function constructor with JSON."""
        code = """
function executeCode(jsonData) {
    return new Function('return ' + JSON.parse(jsonData))();
}
"""
        results = rule.check(code, "app.js", "javascript")
        assert len(results) == 1
        assert "Function" in results[0].description

    def test_detects_node_serialize(self, rule):
        """Should detect node-serialize usage."""
        code = """
const serialize = require('node-serialize');

function process(data) {
    return serialize.unserialize(data);
}
"""
        results = rule.check(code, "app.js", "javascript")
        assert len(results) == 1
        assert "node-serialize" in results[0].description


class TestJavaDeserialization:
    """Test Java deserialization detection."""

    def test_detects_object_input_stream(self, rule):
        """Should detect ObjectInputStream usage."""
        code = """
import java.io.ObjectInputStream;

public class DataLoader {
    public Object loadData(InputStream stream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }
}
"""
        results = rule.check(code, "DataLoader.java", "java")
        assert len(results) >= 1
        assert any("ObjectInputStream" in r.description for r in results)

    def test_detects_xml_decoder(self, rule):
        """Should detect XMLDecoder usage."""
        code = """
import java.beans.XMLDecoder;

public class ConfigLoader {
    public Object loadConfig(InputStream stream) {
        XMLDecoder decoder = new XMLDecoder(stream);
        return decoder.readObject();
    }
}
"""
        results = rule.check(code, "ConfigLoader.java", "java")
        assert len(results) >= 1
        assert any("XMLDecoder" in r.description for r in results)

    def test_detects_jackson_default_typing(self, rule):
        """Should detect Jackson enableDefaultTyping."""
        code = """
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonProcessor {
    public static ObjectMapper getMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper;
    }
}
"""
        results = rule.check(code, "JsonProcessor.java", "java")
        assert len(results) >= 1
        assert any("enableDefaultTyping" in r.description for r in results)


class TestPHPDeserialization:
    """Test PHP deserialization detection."""

    def test_detects_unserialize(self, rule):
        """Should detect unserialize usage."""
        code = """
<?php
function processData($data) {
    return unserialize($data);
}
"""
        results = rule.check(code, "process.php", "php")
        assert len(results) == 1
        assert "unserialize" in results[0].description.lower()


class TestRubyDeserialization:
    """Test Ruby deserialization detection."""

    def test_detects_marshal_load(self, rule):
        """Should detect Marshal.load usage."""
        code = """
def load_data(data)
  Marshal.load(data)
end
"""
        results = rule.check(code, "app.rb", "ruby")
        assert len(results) == 1
        assert "Marshal" in results[0].description

    def test_detects_yaml_load(self, rule):
        """Should detect YAML.load usage in Ruby."""
        code = """
require 'yaml'

def parse_config(config_str)
  YAML.load(config_str)
end
"""
        results = rule.check(code, "config.rb", "ruby")
        assert len(results) == 1
        assert "YAML" in results[0].description


class TestCSharpDeserialization:
    """Test C# deserialization detection."""

    def test_detects_binary_formatter(self, rule):
        """Should detect BinaryFormatter.Deserialize usage."""
        code = """
using System.Runtime.Serialization.Formatters.Binary;

public class DataLoader {
    public object LoadData(Stream stream) {
        BinaryFormatter formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}
"""
        results = rule.check(code, "DataLoader.cs", "csharp")
        assert len(results) == 1
        assert "BinaryFormatter" in results[0].description

    def test_detects_json_net_type_name_handling(self, rule):
        """Should detect Json.NET TypeNameHandling."""
        code = """
using Newtonsoft.Json;

public class JsonProcessor {
    public T Deserialize<T>(string json) {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject<T>(json, settings);
    }
}
"""
        results = rule.check(code, "JsonProcessor.cs", "csharp")
        assert len(results) >= 1
        assert any("TypeNameHandling" in r.description for r in results)


class TestRuleMetadata:
    """Test rule metadata."""

    def test_rule_id(self, rule):
        """Should have correct rule ID."""
        assert rule.rule_id == "SEC-005"

    def test_severity(self, rule):
        """Should be critical severity."""
        assert rule.severity.value == "critical"

    def test_owasp_mapping(self, rule):
        """Should map to correct OWASP category."""
        assert "A08:2021" in rule.owasp_mapping

    def test_cwe_id(self, rule):
        """Should have correct CWE ID."""
        assert rule.cwe_id == "CWE-502"

    def test_supports_multiple_languages(self, rule):
        """Should support multiple languages."""
        assert "python" in rule.languages
        assert "javascript" in rule.languages
        assert "java" in rule.languages
        assert "php" in rule.languages
        assert "ruby" in rule.languages
        assert "csharp" in rule.languages


class TestFixSuggestions:
    """Test fix suggestions."""

    def test_python_fix_suggestion(self, rule):
        """Should provide Python-specific fix suggestions."""
        code = "pickle.loads(data)"
        results = rule.check(code, "app.py", "python")
        assert len(results) == 1
        assert "json" in results[0].suggested_fix.lower() or "safe" in results[0].suggested_fix.lower()

    def test_java_fix_suggestion(self, rule):
        """Should provide Java-specific fix suggestions."""
        code = "ObjectInputStream ois = new ObjectInputStream(stream);"
        results = rule.check(code, "App.java", "java")
        assert len(results) == 1
        assert "filter" in results[0].suggested_fix.lower() or "json" in results[0].suggested_fix.lower()
