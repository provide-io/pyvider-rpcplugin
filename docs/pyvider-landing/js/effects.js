/**
 * Particle effects for the ASCII visualization
 */

/**
 * Collection of effects that can be applied to particles
 */
export const effects = {
  /**
   * Creates a floating movement effect
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  float: (particle, time) => {
    particle.group.translate.x = particle.originalX + 
                                Math.sin(time * particle.speed + particle.phase) * particle.radius;
    particle.group.translate.y = particle.originalY + 
                                Math.cos(time * particle.speed + particle.phase) * particle.radius;
  },
  
  /**
   * Creates a rotation effect around multiple axes
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  rotate: (particle, time) => {
    particle.group.rotate.z = Math.sin(time * particle.speed) * 0.3;
    particle.group.rotate.x = Math.cos(time * particle.speed) * 0.2;
  },
  
  /**
   * Creates a pulsing size effect
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  pulse: (particle, time) => {
    const scale = 0.8 + Math.sin(time * particle.speed) * 0.2;
    particle.group.scale.x = scale;
    particle.group.scale.y = scale;
    particle.group.scale.z = scale;
  },
  
  /**
   * Creates an orbital movement effect
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  orbit: (particle, time) => {
    particle.group.translate.z = particle.originalZ + 
                               Math.sin(time * particle.speed + particle.phase) * particle.radius;
  },
  
  /**
   * Creates a wave-like movement effect
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  wave: (particle, time) => {
    particle.group.translate.y = particle.originalY + 
                               Math.sin(time * 0.5 + particle.originalX * 0.05) * particle.amplitude;
  },
  
  /**
   * Creates a glowing effect by modifying particle color
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  glow: (particle, time) => {
    // This effect would typically modify material properties
    // Here we use a workaround for Zdog by scaling slightly
    const pulseScale = 1 + Math.sin(time * particle.speed) * 0.1;
    particle.shape.stroke = particle.originalStroke * pulseScale;
  },
  
  /**
   * Creates a bounce effect
   * @param {Object} particle - The particle to update
   * @param {number} time - Current time in seconds
   */
  bounce: (particle, time) => {
    // Simple bounce using absolute sine wave
    particle.group.translate.y = particle.originalY + 
                               Math.abs(Math.sin(time * particle.speed)) * particle.amplitude;
  }
};

/**
 * Assigns an effect to a particle based on its character
 * @param {string} char - The ASCII character
 * @returns {string} The name of the effect to apply
 */
export function getEffectForChar(char) {
  // Map specific characters to specific effects for visual consistency
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
  
  // Use mapped effect or choose randomly from available effects
  return effectMap[char] || Object.keys(effects)[Math.floor(Math.random() * Object.keys(effects).length)];
}
