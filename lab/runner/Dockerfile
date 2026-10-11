# The scanner, with the dependencies the repository pins and nothing else.
# Built from the repository root so the pinned requirements are the ones under
# test; the source itself is mounted read-only at run time, so the image does
# not have to be rebuilt to scan a working tree.
FROM python:3.12-slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /hh
