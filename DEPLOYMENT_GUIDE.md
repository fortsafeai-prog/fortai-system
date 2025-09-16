# ForTAI Deployment Guide 🚀

This guide shows you how to deploy ForTAI to a public URL so you can access it from any device including your phone.

## Quick Deploy Options (Recommended)

### Option 1: Railway (Best for Full-Stack) ⭐
**FREE $5 credits, great for full-stack apps with Playwright**

1. **Create account**: Go to [railway.app](https://railway.app) and sign up
2. **Deploy via GitHub**:
   - Create a GitHub repository and push your ForTAI code
   - Connect Railway to your GitHub
   - Deploy each service separately:
     - Backend: Deploy from `./enhanced-backend` folder
     - Frontend: Deploy from `./mock-frontend` folder
     - Website: Deploy from `./website` folder

3. **Environment Variables**:
   - Backend: `PORT=8000`, `NODE_ENV=production`
   - Frontend: `PORT=3000`, `BACKEND_URL=https://your-backend-url.railway.app`
   - Website: `PORT=8080`

### Option 2: Render (Easy Deploy) ⭐
**FREE tier with automatic deployments**

1. **Create account**: Go to [render.com](https://render.com) and sign up
2. **Deploy using render.yaml**:
   - Push code to GitHub
   - Connect Render to your repository
   - It will automatically read the `render.yaml` file we created

### Option 3: Vercel (Frontend) + Railway (Backend)
**Best hybrid approach**

1. **Deploy Frontend to Vercel**:
   - Go to [vercel.com](https://vercel.com)
   - Import your repository
   - Set build directory to `./mock-frontend`

2. **Deploy Backend to Railway**:
   - Deploy `./enhanced-backend` to Railway
   - Set environment variable `BACKEND_URL` in Vercel to point to Railway backend

## Step-by-Step Railway Deployment

### 1. Prepare Your Code
```bash
# Initialize git repository (if not already done)
git init
git add .
git commit -m "Initial ForTAI deployment"

# Push to GitHub
git remote add origin https://github.com/yourusername/fortai.git
git push -u origin main
```

### 2. Deploy Backend Service
1. Go to [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your ForTAI repository
4. **Root Directory**: Set to `enhanced-backend`
5. **Environment Variables**:
   ```
   PORT=8000
   NODE_ENV=production
   PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=false
   ```
6. **Custom Start Command**: `npm start`
7. Click Deploy

### 3. Deploy Frontend Service
1. Create another service in same project
2. **Root Directory**: Set to `mock-frontend`
3. **Environment Variables**:
   ```
   PORT=3000
   BACKEND_URL=https://your-backend-service.railway.app
   ```
4. Click Deploy

### 4. Deploy Website Service
1. Create third service
2. **Root Directory**: Set to `website`
3. **Environment Variables**:
   ```
   PORT=8080
   FRONTEND_URL=https://your-frontend-service.railway.app
   ```
4. Click Deploy

## Alternative: Single Service Deployment

If you prefer one deployment, create this combined server:

```javascript
// combined-server.js
const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 8080;

// Serve static website
app.use(express.static(path.join(__dirname, 'website')));

// Serve frontend on /chat route
app.use('/chat', express.static(path.join(__dirname, 'mock-frontend')));

// API routes (proxy to backend or include backend here)
app.use('/api', require('./enhanced-backend/server'));

app.listen(PORT, () => {
    console.log(`ForTAI running on port ${PORT}`);
});
```

## Environment Variables Summary

### Backend (.env)
```
PORT=8000
NODE_ENV=production
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=false
PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
```

### Frontend (.env)
```
PORT=3000
BACKEND_URL=https://your-backend-url.railway.app
NODE_ENV=production
```

### Website (.env)
```
PORT=8080
FRONTEND_URL=https://your-frontend-url.railway.app
NODE_ENV=production
```

## Testing Your Deployment

Once deployed, you'll get URLs like:
- **Website**: `https://fortai-website-production.railway.app`
- **Chat Interface**: `https://fortai-frontend-production.railway.app`
- **API**: `https://fortai-backend-production.railway.app`

### Test Checklist:
- [ ] Website loads and shows landing page
- [ ] Chat interface loads in Swedish
- [ ] URL analysis works with real screenshots
- [ ] Mobile access works (test on phone)
- [ ] API health check responds: `/health`

## Troubleshooting

### Playwright Issues
If screenshots don't work in production:
1. Ensure `npx playwright install chromium` runs in build
2. Check environment variables are set correctly
3. Verify sufficient memory allocation (>512MB)

### CORS Issues
- Backend already configured for `Access-Control-Allow-Origin: *`
- If issues persist, whitelist specific frontend domains

### Memory Issues
- Railway free tier: 512MB RAM
- Render free tier: 512MB RAM
- Consider optimizing Playwright usage or upgrading plan

## Cost Estimation

### Free Tiers:
- **Railway**: $5 free credits (lasts ~1 month with light usage)
- **Render**: 750 hours/month free (enough for 24/7)
- **Vercel**: Generous free tier for frontend

### Paid Plans (if needed):
- **Railway**: $5/month for hobby projects
- **Render**: $7/month for web services
- **Vercel**: $20/month for team features

## Domain Setup (Optional)

To get a custom domain like `fortai.com`:
1. Buy domain from Namecheap, GoDaddy, etc.
2. In Railway/Render dashboard:
   - Go to Settings → Custom Domain
   - Add your domain
   - Update DNS records as instructed

## Success! 🎉

Once deployed, you can:
- Access ForTAI from any device (phone, tablet, laptop)
- Share the URL with others for testing
- Use it for real URL security analysis
- Monitor usage and performance in the hosting dashboard

Your ForTAI system is now live on the internet! 🌐