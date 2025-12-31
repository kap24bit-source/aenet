ALLOWED_TOPICS = {"programming_concept", "linux_reference"}

def allow_topic(topic: str) -> bool:
    return topic in ALLOWED_TOPICS
