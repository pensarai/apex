/**
 * Physarum (Slime Mold) Simulation Engine
 *
 * A simplified Physarum polycephalum simulation for ASCII rendering.
 * Based on the algorithm by Sage Jenson (https://sagejenson.com/physarum).
 *
 * The simulation consists of:
 * - Agents: Moving particles that deposit trail
 * - Trail map: 2D grid of pheromone concentrations
 * - Sensing: Agents sense trail ahead and turn toward stronger concentrations
 */

import { vec2, add, mul, norm, fromAngle, type Vec2 } from "./play-core/vec2";
import { clamp, random, mod } from "./play-core/num";

// Simulation parameters (tuned for terminal)
const AGENT_COUNT = 400;
const SENS_DIST = 4;          // Sensing distance
const SENS_ANGLE = Math.PI / 5; // ~36 degrees
const MOVE_SPEED = 1.0;
const TURN_SPEED = 0.4;
const DEPOSIT_AMOUNT = 1.0;
const DECAY_RATE = 0.92;
const DIFFUSE_RADIUS = 1;

// ASCII texture for rendering (darkest to brightest)
const ASCII_CHARS = " .,:;+*#@";

interface Agent {
  pos: Vec2;
  angle: number;
}

export class PetriSimulation {
  width: number;
  height: number;
  agents: Agent[];
  trailMap: Float32Array;
  private tempMap: Float32Array;

  constructor(width: number, height: number) {
    this.width = width;
    this.height = height;
    this.agents = [];
    this.trailMap = new Float32Array(width * height);
    this.tempMap = new Float32Array(width * height);

    this.initAgents();
  }

  private initAgents() {
    const cx = this.width / 2;
    const cy = this.height / 2;
    const radius = Math.min(this.width, this.height) * 0.35;

    for (let i = 0; i < AGENT_COUNT; i++) {
      // Spawn agents in a ring pattern pointing inward
      const angle = random(0, Math.PI * 2);
      const r = radius * (0.5 + random(0, 0.5));
      const x = cx + Math.cos(angle) * r;
      const y = cy + Math.sin(angle) * r;

      this.agents.push({
        pos: vec2(x, y),
        angle: angle + Math.PI + random(-0.5, 0.5) // Point roughly inward
      });
    }
  }

  /**
   * Sample trail value at position with wrapping
   */
  private sampleTrail(x: number, y: number): number {
    const ix = mod(Math.floor(x), this.width);
    const iy = mod(Math.floor(y), this.height);
    return this.trailMap[iy * this.width + ix];
  }

  /**
   * Deposit trail at position
   */
  private deposit(x: number, y: number, amount: number) {
    const ix = mod(Math.floor(x), this.width);
    const iy = mod(Math.floor(y), this.height);
    const idx = iy * this.width + ix;
    this.trailMap[idx] = Math.min(1.0, this.trailMap[idx] + amount);
  }

  /**
   * Run one simulation step
   */
  step() {
    // Move and sense for each agent
    for (const agent of this.agents) {
      // Sense in three directions
      const senseForward = this.sense(agent, 0);
      const senseLeft = this.sense(agent, SENS_ANGLE);
      const senseRight = this.sense(agent, -SENS_ANGLE);

      // Determine turn direction based on sensing
      if (senseForward > senseLeft && senseForward > senseRight) {
        // Stay straight
      } else if (senseForward < senseLeft && senseForward < senseRight) {
        // Turn randomly
        agent.angle += (random() > 0.5 ? 1 : -1) * TURN_SPEED;
      } else if (senseLeft > senseRight) {
        // Turn left
        agent.angle += TURN_SPEED;
      } else if (senseRight > senseLeft) {
        // Turn right
        agent.angle -= TURN_SPEED;
      }

      // Move forward
      const dir = fromAngle(agent.angle, MOVE_SPEED);
      agent.pos = add(agent.pos, dir);

      // Wrap position
      agent.pos[0] = mod(agent.pos[0], this.width);
      agent.pos[1] = mod(agent.pos[1], this.height);

      // Deposit trail
      this.deposit(agent.pos[0], agent.pos[1], DEPOSIT_AMOUNT);
    }

    // Diffuse and decay trail
    this.diffuseAndDecay();
  }

  /**
   * Sense trail in a direction
   */
  private sense(agent: Agent, angleOffset: number): number {
    const senseAngle = agent.angle + angleOffset;
    const senseDir = fromAngle(senseAngle, SENS_DIST);
    const sensePos = add(agent.pos, senseDir);
    return this.sampleTrail(sensePos[0], sensePos[1]);
  }

  /**
   * Diffuse trail values to neighbors and decay
   */
  private diffuseAndDecay() {
    // Copy to temp, applying 3x3 blur kernel
    for (let y = 0; y < this.height; y++) {
      for (let x = 0; x < this.width; x++) {
        let sum = 0;
        let count = 0;

        for (let dy = -DIFFUSE_RADIUS; dy <= DIFFUSE_RADIUS; dy++) {
          for (let dx = -DIFFUSE_RADIUS; dx <= DIFFUSE_RADIUS; dx++) {
            const nx = mod(x + dx, this.width);
            const ny = mod(y + dy, this.height);
            sum += this.trailMap[ny * this.width + nx];
            count++;
          }
        }

        const idx = y * this.width + x;
        this.tempMap[idx] = (sum / count) * DECAY_RATE;
      }
    }

    // Swap maps
    const swap = this.trailMap;
    this.trailMap = this.tempMap;
    this.tempMap = swap;
  }

  /**
   * Render to ASCII string array (one string per row)
   */
  render(): string[] {
    const rows: string[] = [];

    for (let y = 0; y < this.height; y++) {
      let row = "";
      for (let x = 0; x < this.width; x++) {
        const value = this.trailMap[y * this.width + x];
        // Map value to ASCII character
        const charIdx = Math.floor(clamp(value, 0, 0.99) * ASCII_CHARS.length);
        row += ASCII_CHARS[charIdx];
      }
      rows.push(row);
    }

    return rows;
  }

  /**
   * Resize simulation (reinitializes)
   */
  resize(width: number, height: number) {
    this.width = width;
    this.height = height;
    this.trailMap = new Float32Array(width * height);
    this.tempMap = new Float32Array(width * height);
    this.agents = [];
    this.initAgents();
  }
}
