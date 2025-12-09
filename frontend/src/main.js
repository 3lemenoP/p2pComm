// P2PComm Frontend Entry Point
import './styles/index.css';
import { initApp } from './app.js';

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
