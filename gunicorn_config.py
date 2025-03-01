import os

# Bind to the port that Render provides
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"

# Worker configuration
workers = 4
threads = 2
timeout = 120
worker_class = 'sync'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Gunicorn configuration
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"' 