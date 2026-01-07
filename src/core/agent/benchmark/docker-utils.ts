import { existsSync, readFileSync, writeFileSync } from "fs";
import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import path from "path";
import yaml from "yaml";

const exec = promisify(nodeExec);

export interface DockerComposePortInfo {
  hostPort: number;
  containerPort: number;
  composeFile: string;
  needsPortMapping: boolean;
  serviceName: string;
}

// Infrastructure service patterns to skip (database, cache, message queue, internal services, etc.)
const INFRASTRUCTURE_PATTERNS = [
  'postgres', 'postgresql', 'pg', 'db', 'database',
  'mysql', 'mariadb',
  'redis', 'memcached',
  'mongodb', 'mongo',
  'rabbitmq', 'kafka',
  'elasticsearch', 'elastic',
  'minio', 'storage',
  'internal',  // Skip internal services (they should only be accessible via SSRF, not directly)
  'backend',   // Skip backend services
  'worker',    // Skip worker services
];

/**
 * Determine if a service is infrastructure (should be skipped)
 */
function isInfrastructureService(serviceName: string): boolean {
  const lowerName = serviceName.toLowerCase();
  return INFRASTRUCTURE_PATTERNS.some(pattern => lowerName.includes(pattern));
}

/**
 * Parse docker-compose file to find the web application service
 * Skips infrastructure services (databases, caches, etc.)
 */
export function parseDockerComposePort(benchmarkPath: string): DockerComposePortInfo {
  // Try docker-compose.yml first, then docker-compose.yaml
  const composePaths = [
    path.join(benchmarkPath, "docker-compose.yml"),
    path.join(benchmarkPath, "docker-compose.yaml"),
  ];

  for (const composePath of composePaths) {
    if (!existsSync(composePath)) {
      continue;
    }

    try {
      const content = readFileSync(composePath, "utf-8");
      const parsed = yaml.parse(content);

      // Look for the web service (skip infrastructure services)
      if (parsed?.services) {
        for (const [serviceName, service] of Object.entries(parsed.services)) {
          // Skip infrastructure services
          if (isInfrastructureService(serviceName)) {
            console.log(`  ⏭️  Skipping infrastructure service: ${serviceName}`);
            continue;
          }

          if (typeof service === "object" && service !== null) {
            const serviceObj = service as any;
            const ports = serviceObj.ports;

            if (ports && Array.isArray(ports) && ports.length > 0) {
              const firstPort = ports[0];

              // Parse port mapping (e.g., "80:80" or "8080:80")
              if (typeof firstPort === "string") {
                const match = firstPort.match(/^(\d+):(\d+)$/);
                if (match && match[1] && match[2]) {
                  console.log(`  ✅ Found web service: ${serviceName} on port ${match[1]}`);
                  return {
                    hostPort: parseInt(match[1], 10),
                    containerPort: parseInt(match[2], 10),
                    composeFile: composePath,
                    needsPortMapping: false,
                    serviceName,
                  };
                }
              } else if (typeof firstPort === "number") {
                console.log(`  ✅ Found web service: ${serviceName} on port ${firstPort}`);
                return {
                  hostPort: firstPort,
                  containerPort: firstPort,
                  composeFile: composePath,
                  needsPortMapping: false,
                  serviceName,
                };
              }
            }

            // Check for expose without ports (needs mapping)
            if (serviceObj.expose && Array.isArray(serviceObj.expose) && serviceObj.expose.length > 0) {
              const exposePort = serviceObj.expose[0];
              const port = typeof exposePort === "string" ? parseInt(exposePort, 10) : exposePort;

              console.log(`  ⚠️  Service ${serviceName} has expose but no ports - will add port mapping`);

              // Add port mapping to the service
              if (!serviceObj.ports) {
                serviceObj.ports = [];
              }
              serviceObj.ports.push(`${port}:${port}`);

              // Write back the modified compose file
              writeFileSync(composePath, yaml.stringify(parsed));
              console.log(`  ✅ Added port mapping ${port}:${port} to ${serviceName}`);

              return {
                hostPort: port,
                containerPort: port,
                composeFile: composePath,
                needsPortMapping: true,
                serviceName,
              };
            }
          }
        }
      }

      // If we get here, no ports were found - find first non-infrastructure service
      console.log(`  ⚠️  No ports found in ${composePath}, adding default port to first web service...`);

      if (parsed?.services) {
        // Find first non-infrastructure service
        for (const [serviceName, service] of Object.entries(parsed.services)) {
          if (isInfrastructureService(serviceName)) {
            continue;
          }

          const serviceObj = service as any;

          // Add common web port mapping
          const defaultPort = 80;
          if (!serviceObj.ports) {
            serviceObj.ports = [];
          }
          serviceObj.ports.push(`${defaultPort}:${defaultPort}`);

          writeFileSync(composePath, yaml.stringify(parsed));
          console.log(`  ✅ Added default port mapping ${defaultPort}:${defaultPort} to ${serviceName}`);

          return {
            hostPort: defaultPort,
            containerPort: defaultPort,
            composeFile: composePath,
            needsPortMapping: true,
            serviceName,
          };
        }
      }
    } catch (error: any) {
      console.error(`Warning: Failed to parse ${composePath}: ${error.message}`);
    }
  }

  // Default to port 80 if not found
  console.log(`  ⚠️  Could not find docker-compose file, defaulting to port 80`);
  return {
    hostPort: 80,
    containerPort: 80,
    composeFile: "",
    needsPortMapping: false,
    serviceName: "unknown",
  };
}

/**
 * Get the actual mapped port from a running Docker container
 * This queries Docker to get the host port that's mapped to the container port
 */
export async function getActualDockerPort(
  benchmarkPath: string,
  serviceName: string,
  containerPort: number = 80
): Promise<number> {
  try {
    // Get the container name from docker-compose
    const { stdout } = await exec(
      `docker compose ps -q ${serviceName}`,
      { cwd: benchmarkPath }
    );

    const containerId = stdout.trim();
    if (!containerId) {
      console.log(`  ⚠️  Could not find running container for service: ${serviceName}`);
      return containerPort;
    }

    // Get the port mapping
    const { stdout: portOutput } = await exec(
      `docker port ${containerId} ${containerPort}`
    );

    // Output format: "0.0.0.0:6340" or "0.0.0.0:6340\n:::6340"
    const match = portOutput.match(/0\.0\.0\.0:(\d+)/);
    if (match && match[1]) {
      const hostPort = parseInt(match[1], 10);
      console.log(`  ✅ Container ${serviceName}:${containerPort} is mapped to localhost:${hostPort}`);
      return hostPort;
    }

    console.log(`  ⚠️  Could not parse port mapping, using container port: ${containerPort}`);
    return containerPort;
  } catch (error: any) {
    console.error(`  ⚠️  Error getting Docker port mapping: ${error.message}`);
    return containerPort;
  }
}
