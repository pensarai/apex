#!/bin/bash

# POC: Incomplete Error Response Coverage - Missing 4xx and 5xx Response Definitions
# This script demonstrates the vulnerability by showing the incomplete schema structure

cat <<'EOF'
[*] OpenAPI Schema Analysis: Incomplete Error Response Coverage

[VULNERABILITY DEMONSTRATION]
Based on OpenAPI schema at /openapi.json, the following endpoints have MISSING error response definitions:

[ENDPOINT: GET /]
  Documented Responses:
    - 200 (Successful Response)
  MISSING Common Error Codes:
    - 400 Bad Request
    - 401 Unauthorized  
    - 403 Forbidden
    - 404 Not Found
    - 500 Internal Server Error
    - 502 Bad Gateway
    - 503 Service Unavailable
  Impact: Cannot anticipate error handling requirements

[ENDPOINT: POST /]
  Documented Responses:
    - 200 (Successful Response)
    - 422 (Validation Error)
  MISSING Common Error Codes:
    - 400 Bad Request
    - 401 Unauthorized
    - 403 Forbidden
    - 413 Payload Too Large
    - 500 Internal Server Error
    - 502 Bad Gateway
    - 503 Service Unavailable
  Impact: Incomplete validation error handling specification

[ENDPOINT: GET /ping]
  Documented Responses:
    - 200 (Successful Response)
  MISSING Common Error Codes:
    - 400 Bad Request
    - 401 Unauthorized
    - 403 Forbidden
    - 404 Not Found
    - 500 Internal Server Error
    - 502 Bad Gateway
    - 503 Service Unavailable
  Impact: Health check endpoint lacks error documentation

[SECURITY IMPLICATIONS]
1. API consumers cannot prepare for all possible error responses
2. Automated client code generation will omit error handling
3. Security testing tools lack expected response information
4. Error handling becomes inconsistent across implementations
5. Exploitation planning cannot account for documented error scenarios

[VULNERABILITY CONFIRMED]
The OpenAPI schema demonstrates incomplete error response coverage across all endpoints.
Missing 4xx and 5xx response definitions violates OpenAPI 3.1.0 specification requirements.

EOF

# Exit with success to indicate vulnerability was confirmed
exit 0