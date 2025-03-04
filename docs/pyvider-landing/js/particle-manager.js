/**
 * Manages the creation and rendering of ASCII character particles
 */
import { getCharColor, getColorVariant } from './utils.js';
import { effects, getEffectForChar } from './effects.js';
import { getCharacterGroups } from './ascii.js';

export class ParticleManager {
  /**
   * Creates a new particle manager
   * @param {Zdog.Illustration} illo - The Zdog illustration to add particles to
   * @param {Array<Array<string>>} asciiGrid - 2D array of ASCII characters
   */
  constructor(illo, asciiGrid) {
    this.illo = illo;
    this.asciiGrid = asciiGrid;
    this.particles = [];
    this.mainGroup = new Zdog.Group({
      addTo: this.illo,
    });
    this.characterGroups = getCharacterGroups();
  }
  
  /**
   * Creates particles for all non-space characters in the ASCII grid
   * @param {Object} options - Configuration options
   */
  createParticles({ scale, offsetX, offsetY }) {
    // Clear any existing particles
    this.particles = [];
    this.mainGroup.children = [];
    
    // Create new particles
    this.asciiGrid.forEach((row, y) => {
      row.forEach((char, x) => {
        if (char.trim() !== '') {
          const particle = this.createParticle(char, x, y, scale, offsetX, offsetY);
          this.particles.push(particle);
        }
      });
    });
  }
  
  /**
   * Creates a single particle for an ASCII character
   * @param {string} char - The ASCII character
   * @param {number} x - Grid x position
   * @param {number} y - Grid y position
   * @param {number} scale - Size scale factor
   * @param {number} offsetX - X position offset
   * @param {number} offsetY - Y position offset
   * @returns {Object} The created particle object
   */
  createParticle(char, x, y, scale, offsetX, offsetY) {
    // Assign effect based on character
    const effectType = getEffectForChar(char);
    
    // Create a group for the particle
    const group = new Zdog.Group({
      addTo: this.mainGroup,
      translate: {
        x: offsetX + x * scale,
        y: offsetY + y * scale,
        z: 0
      },
    });
    
    // Create the character shape
    const shape = this.createCharShape(char, group, scale * 0.8);
    
    // Store original properties for animation reference
    const originalStroke = shape.stroke;
    
    // Generate random animation parameters
    const speed = 0.5 + Math.random() * 1.5;
    const phase = Math.random() * Math.PI * 2;
    const radius = 2 + Math.random() * 3;
    const amplitude = 3 + Math.random() * 5;
    
    // Return particle object with all properties needed for animation
    return {
      char,
      group,
      shape,
      originalX: group.translate.x,
      originalY: group.translate.y,
      originalZ: group.translate.z,
      originalStroke,
      effect: effectType,
      speed,
      phase,
      radius,
      amplitude
    };
  }
  
  /**
   * Creates a shape representing the ASCII character
   * @param {string} char - The ASCII character
   * @param {Zdog.Group} group - Parent group to add shape to
   * @param {number} size - Size of the shape
   * @returns {Zdog.Shape} The created shape
   */
  createCharShape(char, group, size) {
    const strokeWidth = size * 0.2;
    const color = getCharColor(char);
    
    // Choose shape type based on character
    if (this.characterGroups.box.includes(char)) {
      // Block shape
      return new Zdog.Box({
        addTo: group,
        width: size,
        height: size,
        depth: size / 3,
        stroke: strokeWidth,
        color: color,
        frontFace: getColorVariant(color, 1.1),
        backFace: getColorVariant(color, 0.9),
      });
    } else if (this.characterGroups.star.includes(char)) {
      // Star-like shape
      return new Zdog.Shape({
        addTo: group,
        stroke: strokeWidth,
        color: color,
        path: [
          { x: 0, y: -size/2 },
          { x: size/4, y: -size/4 },
          { x: size/2, y: 0 },
          { x: size/4, y: size/4 },
          { x: 0, y: size/2 },
          { x: -size/4, y: size/4 },
          { x: -size/2, y: 0 },
          { x: -size/4, y: -size/4 },
        ],
        closed: true,
      });
    } else if (this.characterGroups.line.includes(char)) {
      // Line shape
      return new Zdog.Shape({
        addTo: group,
        stroke: strokeWidth,
        color: color,
        path: [
          { x: -size/2, y: 0 },
          { x: size/2, y: 0 },
        ],
      });
    } else if (this.characterGroups.dot.includes(char)) {
      // Simple circle
      return new Zdog.Ellipse({
        addTo: group,
        diameter: size,
        stroke: strokeWidth,
        color: color,
      });
    } else {
      // Default shape for other characters
      return new Zdog.Shape({
        addTo: group,
        stroke: strokeWidth,
        color: color,
        path: [
          { x: -size/3, y: -size/3 },
          { x: size/3, y: -size/3 },
          { x: size/3, y: size/3 },
          { x: -size/3, y: size/3 },
        ],
        closed: true,
      });
    }
  }
  
  /**
   * Updates all particles based on their effects
   * @param {number} time - Current time in seconds
   */
  updateParticles(time) {
    this.particles.forEach(particle => {
      const updateEffect = effects[particle.effect];
      if (updateEffect) {
        updateEffect(particle, time);
      }
    });
  }
  
  /**
   * Rotates the main particle group
   * @param {number} rotationX - X-axis rotation
   * @param {number} rotationY - Y-axis rotation
   */
  setRotation(rotationX, rotationY) {
    this.mainGroup.rotate.x = rotationX;
    this.mainGroup.rotate.y = rotationY;
  }
}
