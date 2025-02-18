class PageTransitionHandler {
    constructor() {
        this.overlay = document.querySelector('.page-transition-overlay');
        this.links = document.querySelectorAll('.nav-link');
        this.contentWrapper = document.querySelector('.content-wrapper');
        
        this.init();
    }

    init() {
        // Only initialize for pages that should have transitions
        if (document.body.classList.contains('transition-page')) {
            this.links.forEach(link => {
                link.addEventListener('click', (e) => {
                    // Skip transition for logout
                    if (link.href.includes('logout')) {
                        return;
                    }
                    
                    e.preventDefault();
                    this.transitionToPage(link.href);
                });
            });

            // Show content with animation when page loads
            window.addEventListener('load', () => {
                this.contentWrapper.classList.add('visible');
            });
        }
    }

    async transitionToPage(href) {
        this.overlay.classList.add('active');
        this.contentWrapper.classList.remove('visible');

        // Wait for animation
        await new Promise(resolve => setTimeout(resolve, 500));

        // Navigate to new page
        window.location.href = href;
    }
}

// Initialize page transitions
document.addEventListener('DOMContentLoaded', () => {
    new PageTransitionHandler();
});
