/**
 * Utility functions for the ASCII particle effect application
 */

/**
 * Generates a color mapping for ASCII characters
 * @returns {Object} Mapping of characters to colors
 */
export function getColorMap() {
  return {
    ':': '#55FFFF',  // Cyan
    '@': '#FF55FF',  // Magenta
    '=': '#FFFF55',  // Yellow
    '-': '#55FF55',  // Green
    '+': '#FF5555',  // Red
    '%': '#5555FF',  // Blue
    '.': '#FFFFFF',  // White
    '#': '#FF8800',  // Orange
    '*': '#00FF88',  // Mint
    default: '#FFFFFF' // Default white
  };
}

/**
 * Gets the color for a specific character
 * @param {string} char - The character to get color for
 * @returns {string} Hex color code
 */
export function getCharColor(char) {
  const colorMap = getColorMap();
  return colorMap[char] || colorMap.default;
}

/**
 * Creates a color variant for gradients and lighting effects
 * @param {string} color - Base hex color
 * @param {number} factor - Multiplier for brightness (>1 brightens, <1 darkens)
 * @returns {string} Modified hex color
 */
export function getColorVariant(color, factor) {
  const r = parseInt(color.slice(1, 3), 16);
  const g = parseInt(color.slice(3, 5), 16);
  const b = parseInt(color.slice(5, 7), 16);
  
  const adjustColor = (c) => {
    const adjusted = Math.floor(c * factor);
    return Math.min(255, Math.max(0, adjusted));
  };
  
  return `#${
    adjustColor(r).toString(16).padStart(2, '0')
  }${
    adjustColor(g).toString(16).padStart(2, '0')
  }${
    adjustColor(b).toString(16).padStart(2, '0')
  }`;
}

/**
 * Gets pointer position from mouse or touch event
 * @param {Event} event - Mouse or touch event
 * @returns {Object} x and y coordinates
 */
export function getPointerPosition(event) {
  // Prevent default behavior for touch events to avoid scrolling
  if (event.type.startsWith('touch')) {
    event.preventDefault();
  }
  
  const x = event.touches ? event.touches[0].clientX : event.clientX;
  const y = event.touches ? event.touches[0].clientY : event.clientY;
  return { x, y };
}

/**
 * Debounce function to limit how often a function can be called
 * @param {Function} func - Function to debounce
 * @param {number} wait - Milliseconds to wait
 * @returns {Function} Debounced function
 */
export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}
