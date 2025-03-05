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
    const originalStroke = shape.stroke || 0;
    
    // Generate random animation parameters
    const speed = 0.3 + Math.random() * 0.8; // Slower speed for more gentle animation
    const phase = Math.random() * Math.PI * 2;
    const radius = 1 + Math.random() * 2;    // Smaller radius for subtler movement
    const amplitude = 2 + Math.random() * 3; // Smaller amplitude
    
    // Assign default effect for rotation and throbbing
    const effectType = getEffectForChar(char);
    
    // Store secondary effect (if any)
    const secondaryEffect = (() => {
      // Map specific characters to specific effects for visual variety
      const effectMap = {
        '@': 'pulse',
        '#': 'orbit',
        '*': 'glow',
        '+': 'rotate',
        ':': 'float',
        '.': 'float',
        '=': 'wave',
        '-': 'wave',
        '%': 'bounce'
      };
      return effectMap[char];
    })();
    
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
      secondaryEffect,
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
    const strokeWidth = size * 0.15;
    const color = getCharColor(char);
    const depth = size * 0.25; // Add depth to make it 3D
    
    // Create a 3D panel for the character with some depth
    const panel = new Zdog.Box({
      addTo: group,
      width: size * 0.9,
      height: size * 0.9,
      depth: depth,
      stroke: 0,
      color: getColorVariant(color, 0.8),
      frontFace: color,
      backFace: getColorVariant(color, 0.7),
      leftFace: getColorVariant(color, 0.6),
      rightFace: getColorVariant(color, 0.6),
      topFace: getColorVariant(color, 0.9),
      bottomFace: getColorVariant(color, 0.5),
    });
    
    // Create the actual character on top of the panel
    // Use character-specific rendering based on the ASCII character
    let charShape;
    
    if (char === '@') {
      // Create a circular 'at' symbol
      charShape = new Zdog.Ellipse({
        addTo: panel,
        diameter: size * 0.7,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
      });
      
      // Add a smaller circle inside
      new Zdog.Ellipse({
        addTo: charShape,
        diameter: size * 0.3,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { x: size * 0.1, y: -size * 0.05 },
      });
    } else if (char === '#') {
      // Hash/pound symbol
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: [
          { x: -size/4, y: -size/3 },
          { x: -size/4, y: size/3 },
          { move: { x: size/4, y: -size/3 } },
          { x: size/4, y: size/3 },
          { move: { x: -size/3, y: -size/4 } },
          { x: size/3, y: -size/4 },
          { move: { x: -size/3, y: size/4 } },
          { x: size/3, y: size/4 },
        ],
      });
    } else if (this.characterGroups.star.includes(char)) {
      // Star-like characters
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: [
          { x: 0, y: -size/3 },
          { x: size/8, y: -size/8 },
          { x: size/3, y: -size/8 },
          { x: size/5, y: size/8 },
          { x: size/4, y: size/3 },
          { x: 0, y: size/5 },
          { x: -size/4, y: size/3 },
          { x: -size/5, y: size/8 },
          { x: -size/3, y: -size/8 },
          { x: -size/8, y: -size/8 },
        ],
        closed: true,
      });
    } else if (this.characterGroups.line.includes(char)) {
      // Line characters
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: char === '-' 
          ? [{ x: -size/3, y: 0 }, { x: size/3, y: 0 }]
          : [{ x: -size/3, y: -size/6 }, { x: size/3, y: -size/6 }, 
             { move: { x: -size/3, y: size/6 } }, { x: size/3, y: size/6 }],
      });
    } else if (this.characterGroups.dot.includes(char)) {
      // Dots and colons
      const isColon = char === ':';
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: isColon
          ? [{ x: 0, y: -size/5 }, { move: { x: 0, y: size/5 } }, {}]
          : [{ x: 0, y: 0 }],
      });
    } else if (char === '%') {
      // Percent symbol
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: [
          // Diagonal line
          { x: -size/3, y: size/3 },
          { x: size/3, y: -size/3 },
          // Top circle (move and then add small circle)
          { move: { x: -size/5, y: -size/5 } },
        ],
      });
      
      // Add small circles for percent
      new Zdog.Ellipse({
        addTo: charShape,
        diameter: size * 0.2,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { x: -size/5, y: -size/5 },
      });
      
      new Zdog.Ellipse({
        addTo: charShape,
        diameter: size * 0.2,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { x: size/5, y: size/5 },
      });
    } else {
      // Default for any other character - simple square
      charShape = new Zdog.Shape({
        addTo: panel,
        stroke: strokeWidth,
        color: '#FFFFFF',
        translate: { z: depth/2 + 1 },
        path: [
          { x: -size/4, y: -size/4 },
          { x: size/4, y: -size/4 },
          { x: size/4, y: size/4 },
          { x: -size/4, y: size/4 },
        ],
        closed: true,
      });
    }
    
    return panel; // Return the main panel for animation
  }
  
  /**
   * Updates all particles based on their effects
   * @param {number} time - Current time in seconds
   */
  updateParticles(time) {
    this.particles.forEach(particle => {
      // Apply the main effect (rotateAndThrob)
      const updateEffect = effects[particle.effect];
      if (updateEffect) {
        updateEffect(particle, time);
      }
      
      // Apply secondary effect if specified
      if (particle.secondaryEffect && effects[particle.secondaryEffect]) {
        // Apply secondary effect with reduced intensity
        const secondaryEffect = effects[particle.secondaryEffect];
        
        // Save original properties
        const origScale = { ...particle.group.scale };
        const origTranslate = { ...particle.group.translate };
        const origRotate = { ...particle.group.rotate };
        
        // Apply secondary effect
        secondaryEffect(particle, time);
        
        // Blend back with original properties (70% main effect, 30% secondary)
        particle.group.scale.x = particle.group.scale.x * 0.3 + origScale.x * 0.7;
        particle.group.scale.y = particle.group.scale.y * 0.3 + origScale.y * 0.7;
        particle.group.scale.z = particle.group.scale.z * 0.3 + origScale.z * 0.7;
        
        particle.group.translate.x = particle.group.translate.x * 0.3 + origTranslate.x * 0.7;
        particle.group.translate.y = particle.group.translate.y * 0.3 + origTranslate.y * 0.7;
        particle.group.translate.z = particle.group.translate.z * 0.3 + origTranslate.z * 0.7;
        
        particle.group.rotate.x = particle.group.rotate.x * 0.3 + origRotate.x * 0.7;
        particle.group.rotate.y = particle.group.rotate.y * 0.3 + origRotate.y * 0.7;
        particle.group.rotate.z = particle.group.rotate.z * 0.3 + origRotate.z * 0.7;
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
