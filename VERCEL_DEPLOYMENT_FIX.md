# 🚀 Vercel Deployment Fix - CSRF Token 404 Error

## 📋 Issue Summary
Your Express.js application is deployed to Vercel but API endpoints (like `/api/csrf-token`) are returning 404 errors because Vercel doesn't know how to route API requests to your Express server.

## ✅ Solution Implemented

### 1. **Created `vercel.json` Configuration** ✅
The `vercel.json` file has been created in your project root with proper routing configuration.

### 2. **Updated `package.json`** ✅
Added build script and Node.js version specification for Vercel compatibility.

## 🔧 Next Steps to Deploy

### **Step 1: Commit and Push Changes**
```bash
git add .
git commit -m "Add Vercel configuration for API routing"
git push origin main
```

### **Step 2: Configure Environment Variables in Vercel**
Go to your Vercel dashboard → Project Settings → Environment Variables and add:

#### **Required Environment Variables:**
```env
NODE_ENV=production
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_64_character_jwt_secret
SESSION_SECRET=your_session_secret
ENCRYPTION_KEY=your_encryption_key
EMAIL_USER=your_gmail_email
EMAIL_PASS=your_gmail_app_password
RECAPTCHA_SECRET_KEY=your_recaptcha_secret
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
```

#### **Security Environment Variables:**
```env
HSTS_ENABLED=true
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true
HSTS_PRELOAD=true
BCRYPT_SALT_ROUNDS=12
```

⚠️ **IMPORTANT**: Replace the hardcoded values in `src/config/config.js` with proper environment variables for security.

### **Step 3: Redeploy Application**
1. Go to Vercel Dashboard
2. Click on your project
3. Go to "Deployments" tab
4. Click "Redeploy" on the latest deployment
5. Or simply push a new commit to trigger auto-deployment

### **Step 4: Update CORS Configuration for Production**
Your current CORS config needs to be updated for production. In `src/server.js`, the CORS configuration should specify your actual domain:

```javascript
app.use(cors({
    credentials: true,
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://your-app-name.vercel.app', 'https://your-custom-domain.com']
        : true
}));
```

## 🔍 Testing the Fix

After redeployment, test these endpoints:
- ✅ `https://your-app.vercel.app/api/csrf-token`
- ✅ `https://your-app.vercel.app/api/test`
- ✅ `https://your-app.vercel.app/` (should load your app)

## 🛠️ What the `vercel.json` Does

1. **Builds**: Tells Vercel to build your Express.js server as a Node.js function
2. **API Routes**: Routes all `/api/*` requests to your Express server
3. **Static Files**: Properly serves CSS, JS, images from the `public` folder
4. **Fallback**: Routes all other requests to your Express server for handling

## 🔧 Common Issues & Solutions

### **Issue**: Still getting 404 after deployment
**Solution**: 
1. Check Vercel function logs in dashboard
2. Ensure all environment variables are set
3. Verify the build completed successfully

### **Issue**: CORS errors in production
**Solution**: Update the CORS origin configuration to include your Vercel domain

### **Issue**: Database connection errors
**Solution**: Ensure `MONGODB_URI` is correctly set in Vercel environment variables

## 📊 Expected Results

After this fix:
- ✅ `/api/csrf-token` will return `{"csrfToken": "..."}`
- ✅ Login form will work properly
- ✅ All API endpoints will be accessible
- ✅ Static files (CSS, JS) will load correctly
- ✅ HTTPS security headers will be properly configured

## 🚨 Security Reminders

1. **Remove hardcoded secrets** from `src/config/config.js`
2. **Set strong environment variables** in Vercel dashboard
3. **Enable HSTS** for production (already configured)
4. **Update CORS origins** to your actual domain
5. **Monitor Vercel function logs** for any security issues

---

**Next Steps**: Commit the changes, set environment variables in Vercel, and redeploy. Your CSRF token endpoint should work immediately after redeployment! 