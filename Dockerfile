FROM pypy:3.7-slim

RUN apt update \
    && apt -y upgrade \
    && apt install -y \
    && apt purge gcc -y \
    && apt autoremove -y \
    && rm -rf /root/.cache/ \
    && rm -rf /var/lib/{apt,dpkg}/ \
    && pip install dnspython tqdm

COPY *.py /cyclehunter/

WORKDIR /cyclehunter