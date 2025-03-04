/**
 * Main application entry point
 */
import { parseAsciiArt, getGridDimensions } from './ascii.js';
import { ParticleManager } from './particle-manager.js';
import { getPointerPosition, debounce } from './utils.js';

/**
 * Main application class for ASCII particle visualization
 */
class AsciiParticleApp {
  /**
   * Initialize the application
   */
  constructor() {
    // Parse the ASCII art
    this.asciiGrid = parseAsciiArt();
    this.gridDimensions = getGridDimensions(this.asciiGrid);
    
    // Initialize state
    this.canvas = document.getElementById('zdog-canvas');
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;
    this.rotationX = 0;
    this.rotationY = 0;
    this.previousTime = 0;
    
    // Set up Zdog and particles
    this.setupZdog();
    this.setupParticles();
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Start animation loop
    this.animate();
    
    // Log initialization
    console.log('ASCII Particle App initialized', {
      gridDimensions: this.gridDimensions,
      particleCount: this.particleManager.particles.length
    });
  }
  
  /**
   * Set up the Zdog illustration
   */
  setupZdog() {
    // Update canvas size
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
    
    // Create Zdog illustration
    this.illo = new Zdog.Illustration({
      element: this.canvas,
      dragRotate: false, // We handle drag manually
      resize: true,
      zoom: 1,
    });
  }
  
  /**
   * Set up particle system
   */
  setupParticles() {
    // Calculate scale to fit the grid on screen with padding
    const padding = 40;
    const scaleX = (window.innerWidth - padding * 2) / this.gridDimensions.width;
    const scaleY = (window.innerHeight - padding * 2) / this.gridDimensions.height;
    const scale = Math.min(scaleX, scaleY) * 0.8;
    
    // Calculate offsets to center the grid
    const offsetX = -this.gridDimensions.width * scale / 2;
    const offsetY = -this.gridDimensions.height * scale / 2;
    
    // Create particle manager
    this.particleManager = new ParticleManager(this.illo, this.asciiGrid);
    this.particleManager.createParticles({ scale, offsetX, offsetY });
  }
  
  /**
   * Set up event listeners for interaction
   */
  setupEventListeners() {
    // Mouse events for future interaction (not for rotation)
    this.canvas.addEventListener('mousedown', this.handleMouseDown.bind(this));
    window.addEventListener('mousemove', this.handleMouseMove.bind(this));
    window.addEventListener('mouseup', this.handleMouseUp.bind(this));
    
    // Touch events
    this.canvas.addEventListener('touchstart', this.handleMouseDown.bind(this), { passive: false });
    window.addEventListener('touchmove', this.handleMouseMove.bind(this), { passive: false });
    window.addEventListener('touchend', this.handleMouseUp.bind(this));
    
    // Window resize
    window.addEventListener('resize', debounce(this.handleResize.bind(this), 250));
    
    // Prevent context menu on right-click
    this.canvas.addEventListener('contextmenu', (e) => e.preventDefault());
  }
  
  /**
   * Handle mouse down event
   * @param {Event} event - Mouse or touch event
   */
  handleMouseDown(event) {
    event.preventDefault();
    this.isDragging = true;
    
    // Get pointer position
    const pointer = getPointerPosition(event);
    
    // For now, we're just tracking the state
    // Future interactions can be added here
    console.log('Mouse down at', pointer);
  }
  
  /**
   * Handle mouse move event
   * @param {Event} event - Mouse or touch event
   */
  handleMouseMove(event) {
    if (!this.isDragging) return;
    
    // Get current pointer position
    const pointer = getPointerPosition(event);
    
    // Future mouse move interactions can be added here
    // For now, we're just logging
    console.log('Mouse move at', pointer);
  }
  
  /**
   * Handle mouse up event
   */
  handleMouseUp() {
    this.isDragging = false;
    console.log('Mouse up');
  }
  
  /**
   * Handle window resize
   */
  handleResize() {
    // Update canvas size
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
    
    // Re-create particles with new sizing
    this.setupParticles();
  }
  
  /**
   * Animation loop
   * @param {DOMHighResTimeStamp} timestamp - Current timestamp
   */
  animate(timestamp = 0) {
    // Calculate time in seconds for animations
    const time = timestamp / 1000;
    
    // Set a fixed rotation instead of using mouse control
    // This creates a subtle, constant movement
    this.rotationY = Math.sin(time * 0.1) * 0.2;
    this.rotationX = Math.cos(time * 0.1) * 0.1;
    this.particleManager.setRotation(this.rotationX, this.rotationY);
    
    // Update all particles
    this.particleManager.updateParticles(time);
    
    // Render the scene
    this.illo.updateRenderGraph();
    
    // Continue animation loop
    requestAnimationFrame(this.animate.bind(this));
  }
}

// Initialize when the document is ready
document.addEventListener('DOMContentLoaded', () => {
  window.app = new AsciiParticleApp();
});
