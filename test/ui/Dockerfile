# Headless Chromium for the web UI smoke test: Microsoft's Playwright image
# has the browsers; the Python package matching them goes on top.
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir playwright==1.48.0
COPY smoke.py /ui/smoke.py
ENV HOME=/tmp
ENTRYPOINT ["python3", "/ui/smoke.py"]
