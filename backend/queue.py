import redis


redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=None,
) 

QUEUE_NAME = "recon_jobs"

