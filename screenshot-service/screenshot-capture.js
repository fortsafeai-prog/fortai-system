const { chromium } = require('playwright');

class ScreenshotService {
    constructor() {
        this.browser = null;
    }

    async initialize() {
        try {
            this.browser = await chromium.launch({
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--disable-extensions'
                ]
            });
            console.log('✅ Playwright browser initialized');
            return true;
        } catch (error) {
            console.error('❌ Failed to initialize browser:', error.message);
            return false;
        }
    }

    async captureScreenshot(url, timeout = 10000) {
        if (!this.browser) {
            throw new Error('Browser not initialized');
        }

        const context = await this.browser.newContext({
            viewport: { width: 1280, height: 720 },
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        });

        const page = await context.newPage();

        try {
            console.log(`📷 Capturing screenshot of: ${url}`);

            // Navigate to the page
            const startTime = Date.now();
            await page.goto(url, {
                waitUntil: 'domcontentloaded',
                timeout: timeout
            });

            // Wait a bit for dynamic content to load
            await page.waitForTimeout(2000);

            const loadTime = Date.now() - startTime;

            // Get page info
            const title = await page.title();
            const finalUrl = page.url();

            // Get page dimensions for full page screenshot
            const dimensions = await page.evaluate(() => {
                return {
                    width: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
                    height: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)
                };
            });

            // Take screenshot
            const screenshot = await page.screenshot({
                fullPage: true,
                type: 'png'
            });

            // Convert to base64
            const screenshotBase64 = screenshot.toString('base64');

            // Analyze forms and elements
            const pageAnalysis = await page.evaluate(() => {
                const forms = Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                        type: input.type,
                        name: input.name,
                        placeholder: input.placeholder
                    }))
                }));

                const links = Array.from(document.querySelectorAll('a[href]')).length;
                const images = Array.from(document.querySelectorAll('img[src]')).length;
                const scripts = Array.from(document.querySelectorAll('script[src]')).length;

                const metaDescription = document.querySelector('meta[name="description"]');

                return {
                    forms,
                    links,
                    images,
                    scripts,
                    metaDescription: metaDescription ? metaDescription.getAttribute('content') : '',
                    hasLoginForm: forms.some(form =>
                        form.inputs.some(input => input.type === 'password')
                    )
                };
            });

            console.log(`✅ Screenshot captured successfully (${loadTime}ms)`);

            return {
                success: true,
                screenshot_base64: screenshotBase64,
                page_title: title,
                final_url: finalUrl,
                load_time_ms: loadTime,
                dimensions,
                analysis: pageAnalysis,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error(`❌ Screenshot failed for ${url}:`, error.message);

            return {
                success: false,
                error: error.message,
                screenshot_base64: null,
                page_title: null,
                timestamp: new Date().toISOString()
            };
        } finally {
            await page.close();
            await context.close();
        }
    }

    async close() {
        if (this.browser) {
            await this.browser.close();
            console.log('🔒 Browser closed');
        }
    }
}

module.exports = ScreenshotService;