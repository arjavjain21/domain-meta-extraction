# 🚀 Deployment Guide

## GitHub Repository Setup

Since `gh` CLI is not available, here are the manual steps to create your public repository:

### 1. Create GitHub Repository

1. Go to [GitHub](https://github.com) and click "New repository"
2. Repository name: `domain-meta-extractor`
3. Description: `🔍 Web app for extracting meta titles and descriptions from domain names with intelligent fallback strategies`
4. Select **Public**
5. Don't initialize with README (we already have one)
6. Click "Create repository"

### 2. Push to GitHub

```bash
cd "/Users/arjavjain/Downloads/hyperke/Automations/Python Scripts"

# Add the remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/domain-meta-extractor.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### 3. Deploy to Streamlit Cloud

1. Go to [Streamlit Cloud](https://share.streamlit.io)
2. Click "New app"
3. Connect your GitHub repository
4. Select `domain-meta-extractor` repository
5. Main file path: `app.py`
6. Click "Deploy"

## Local Testing

### Quick Test

```bash
cd "/Users/arjavjain/Downloads/hyperke/Automations/Python Scripts"

# Install dependencies
pip3 install -r requirements_streamlit.txt

# Run the app
streamlit run app.py
```

Then open your browser to `http://localhost:8501`

### Test with Sample Data

1. Run the app with `streamlit run app.py`
2. Upload the sample file: `data/sample_domains.csv`
3. Click "Extract Meta Information"
4. Download the results

## Alternative Deployment Options

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements_streamlit.txt .
RUN pip install --no-cache-dir -r requirements_streamlit.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run the app
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
```

Build and run:
```bash
docker build -t domain-meta-extractor .
docker run -p 8501:8501 domain-meta-extractor
```

### Heroku Deployment

1. Create `Procfile`:
   ```
   web: streamlit run app.py --server.port=$PORT --server.address=0.0.0.0
   ```

2. Create `runtime.txt`:
   ```
   python-3.9.16
   ```

3. Deploy:
   ```bash
   heroku create your-app-name
   git push heroku main
   heroku ps:scale web=1
   ```

### PythonAnywhere Deployment

1. Upload your code to PythonAnywhere
2. Create a virtual environment and install dependencies
3. Create a web app using the manual configuration
4. Set the command to: `streamlit run app.py --server.port=8080`

## Environment Variables

For production deployments, you can set these environment variables:

```bash
# Streamlit configuration
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_HEADLESS=true

# Performance tuning
MAX_DOMAINS_PER_REQUEST=100
DEFAULT_CONCURRENCY=10
ENABLE_JS_FALLBACK=false
```

## Monitoring and Analytics

### Streamlit Analytics

Add this to your `app.py` for basic analytics:

```python
import streamlit as st

# Add to the top of your app
st.set_page_config(
    page_title="Domain Meta Extractor",
    page_icon="🔍",
    layout="wide"
)

# Add usage tracking
if 'page_views' not in st.session_state:
    st.session_state.page_views = 0
st.session_state.page_views += 1
```

### Custom Analytics

You can integrate Google Analytics or other tracking tools by adding the tracking script to your app.

## Security Considerations

1. **Input Validation**: The app validates domain formats
2. **Rate Limiting**: Built-in throttling prevents abuse
3. **File Upload Limits**: Streamlit has built-in file size limits
4. **No Persistent Storage**: Results are generated on-demand

## Performance Optimization

### For High Traffic

1. **Enable Caching**: Add Streamlit caching
   ```python
   @st.cache_data(ttl=3600)
   def extract_domain_cached(domain):
       # Your extraction logic
   ```

2. **Use Redis**: For session management and caching
3. **Load Balancing**: Deploy multiple instances behind a load balancer

### For Large Files

1. **Chunk Processing**: Process large CSV files in chunks
2. **Background Tasks**: Use Celery for long-running tasks
3. **Database Storage**: Store results in a database instead of memory

## Troubleshooting

### Common Deployment Issues

1. **Import Errors**: Ensure all dependencies are in `requirements_streamlit.txt`
2. **Permission Errors**: Make sure the app has permission to write temporary files
3. **Timeout Errors**: Increase timeout settings for large files
4. **Memory Issues**: Limit concurrent processing and file sizes

### Debug Mode

Run with debugging enabled:
```bash
streamlit run app.py --logger.level=debug
```

## Getting Help

- 📖 [Streamlit Documentation](https://docs.streamlit.io/)
- 🐛 [GitHub Issues](https://github.com/YOUR_USERNAME/domain-meta-extractor/issues)
- 💬 [Streamlit Community](https://discuss.streamlit.io/)

---

**Ready to deploy?** Follow the GitHub setup steps above to get your app live! 🚀