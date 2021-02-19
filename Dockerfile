FROM pypy:3.7-slim

RUN pip install dnspython tqdm

COPY *.py /cyclehunter/

WORKDIR /cyclehunter