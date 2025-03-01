import os
import multiprocessing

# Gunicorn configuration
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
worker_class = 'sync'
errorlog = '-'
loglevel = 'debug'
accesslog = '-'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"' 