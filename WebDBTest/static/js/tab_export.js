/**
 * Simple module for handling server-side archive generation
 */
function triggerArchiveExport() {
    // Currently handled via direct link, but logic can be extended here
    location.href = '/api/export';
}