FROM pypy:3.7-slim

RUN pip install dnspython tqdm async_lru

COPY *.py /cyclehunter/

WORKDIR /cyclehunter
