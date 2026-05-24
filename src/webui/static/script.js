/* RIG Scanner Web UI - Custom JavaScript */

document.addEventListener('DOMContentLoaded', function() {
  initializeTooltips();
});

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
  const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  if (tooltipTriggerList.length > 0 && typeof bootstrap !== 'undefined') {
    [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
  }
}

/**
 * Format a duration in seconds to human-readable format
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration string
 */
function formatDuration(seconds) {
  if (seconds == null) return '—';
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${minutes}m ${secs}s`;
}

/**
 * Format an ISO timestamp to local datetime string
 * @param {string} isoString - ISO 8601 datetime string
 * @returns {string} Formatted local datetime
 */
function formatDatetime(isoString) {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    return date.toLocaleString();
  } catch {
    return isoString.substring(0, 19).replace('T', ' ');
  }
}

/**
 * Get CSS class for grade badge
 * @param {string} grade - Grade letter (A-F)
 * @returns {string} CSS class name
 */
function getGradeClass(grade) {
  if (!grade) return 'bg-secondary';
  const g = grade.toUpperCase();
  const gradeMap = {
    'A': 'bg-success',
    'B': 'bg-primary',
    'C': 'bg-warning',
    'D': 'bg-warning',
    'F': 'bg-danger',
  };
  return gradeMap[g] || 'bg-secondary';
}

/**
 * Get CSS class for status badge
 * @param {string} status - Status string
 * @returns {string} Bootstrap badge class
 */
function getStatusBadgeClass(status) {
  const s = (status || '').toLowerCase();
  const map = {
    'done': 'bg-success',
    'running': 'bg-info',
    'pending': 'bg-secondary',
    'error': 'bg-danger',
  };
  return map[s] || 'bg-secondary';
}

/**
 * Escape HTML for safe display
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  if (text == null) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Truncate text to a maximum length
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
function truncate(text, maxLength = 50) {
  if (!text || text.length <= maxLength) return text || '';
  return text.substring(0, maxLength - 3) + '...';
}

// Export utilities for use in templates
window.RIG = {
  formatDuration,
  formatDatetime,
  getGradeClass,
  getStatusBadgeClass,
  escapeHtml,
  truncate,
};
