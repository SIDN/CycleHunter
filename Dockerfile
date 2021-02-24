FROM python:3.9.2-slim-buster

ENV APP_DIR /cyclehunter

WORKDIR ${APP_DIR}

COPY *.py requirements.txt ${APP_DIR}/

RUN pip install -r requirements.txt
